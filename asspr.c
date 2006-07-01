/***************************************************************************
 *            asspr.c
 *
 *  Anti-Spam Server Proxy Report
 *  Copyright 2005 Obsidian-Studios, Inc.
 *  Author William L. Thomson Jr.
 *         wlt@obsidian-studios.com
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <sys/dir.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define VERSION "0.1.6"
#define SEPARATOR "--------------------------------------------------------------\n"

char **dirs = NULL;
char **omit = NULL;
unsigned short dirs_length = 0;
unsigned short omit_length = 0;
unsigned short rpts = 0;
unsigned short email_allocated = 0;
unsigned short domain_allocated = 0;
unsigned short include_zero = 0;
int yday;
int year;
int hour;
int minute;
unsigned short buffer_size = sizeof(char)*2048;
unsigned short line_buff_size = sizeof(char)*256;
struct tm *tm_ptr = NULL;
struct report *rpts_ptr = NULL;

struct report {
	char *domain;
	unsigned short emails;
	unsigned short omitted;
	unsigned short total;
	struct sub_report *sub_ptr;
	unsigned short sub_count;
};
struct sub_report {
	char *address;
	unsigned short emails;
	unsigned short omitted;
	unsigned short total;
	char *data;
	unsigned int data_length;
};
void init_rpt_ptr() {
	rpts_ptr = calloc(1,sizeof(struct report));
	rpts_ptr->domain = NULL;
	rpts_ptr->emails = 0;
	rpts_ptr->omitted = 0;
	rpts_ptr->total = 0;
	rpts_ptr->sub_count = 0;
	rpts = 0;
}
void init_sub_ptr(struct sub_report *sub_ptr) {
	sub_ptr->address = NULL;
	sub_ptr->emails = 0;
	sub_ptr->omitted = 0;
	sub_ptr->total = 0;
	sub_ptr->data = calloc(buffer_size,sizeof(char));
	sub_ptr->data_length = buffer_size;
}
short omitEmail(char *subject) {
	if(omit==NULL || omit_length==0)
		return(0);
	int o;
	for(o=0;o<omit_length;o++)
		if(strstr(subject,omit[o])!=NULL)
			return(1);
	return(0);
}
short inDateRange(struct tm *file_tm_ptr) {
	if((yday==0 || yday<=file_tm_ptr->tm_yday) &&
	   (year==0 || year<=file_tm_ptr->tm_year))
		return(1);
	else
		return(0);
}
short createReport(char *directory) {
	DIR *dp;
	if((dp = opendir(directory))==NULL) {
		fprintf(stderr,"Could not open %s \n",directory);
        return(1);
    }
    struct direct *dir;
    while((dir = readdir(dp))!=NULL) {
        if(dir->d_ino == 0)
            continue;
		if(strncasecmp(dir->d_name,".",1)==0 ||
		   strncasecmp(dir->d_name,"..",2)==0)
			continue;
		char *file_name = calloc(line_buff_size,sizeof(char));
		strcpy(file_name,directory);
		strcat(file_name,dir->d_name);
		struct stat buf;
		if(stat(file_name,&buf)==-1) {
			continue;
		}
		time_t file_time = buf.st_mtime;
		struct tm *file_tm_ptr = localtime(&file_time);
		if(inDateRange(file_tm_ptr)==1) {
			FILE *fp;
			if((fp = fopen(file_name,"r"))==NULL) {
				fprintf(stderr,"Could open for reading %s\n",file_name);
				continue;
			}
			int results = 0;
			char line[line_buff_size];
			char to[line_buff_size];
			char from[line_buff_size];
			char subject[line_buff_size];
			while(fgets(line,line_buff_size-1,fp)!=NULL) {
				if(strncasecmp(line,"From",4)==0) {
					strcpy(from,line);
					results++;
					if(results==3)
						break;
					else
						continue;
				} else if(strncasecmp(line,"To",2)==0) {
					strcpy(to,line);
					results++;
					if(results==3)
						break;
					else
						continue;
				} else if(strncasecmp(line,"Subject",7)==0) {
					if(omitEmail(line)==1) {
						int r;
						for(r=0;r<rpts;r++) {
							if(strstr(from,rpts_ptr[r].domain)!=NULL ||
							   strstr(to,rpts_ptr[r].domain)!=NULL) {
								int a;
								for(a=0;a<rpts_ptr[r].sub_count;a++) {
									if(strstr(from,rpts_ptr[r].sub_ptr[a].address)!=NULL ||
									   strstr(to,rpts_ptr[r].sub_ptr[a].address)!=NULL) {
										rpts_ptr[r].sub_ptr[a].omitted++;
										rpts_ptr[r].sub_ptr[a].total = rpts_ptr[r].sub_ptr[a].emails + rpts_ptr[r].sub_ptr[a].omitted;
										rpts_ptr[r].omitted++;
										rpts_ptr[r].total = rpts_ptr[r].emails + rpts_ptr[r].omitted;
									}
								}
							}
						}
						break;
					} else {
						strcpy(subject,line);
						results++;
						if(results==3)
							break;
						else
							continue;
					}
				}
				memset(line,'\0',line_buff_size);
			}
			if(results==3) {
				int r;
				for(r=0;r<rpts;r++) {
					if(strstr(from,rpts_ptr[r].domain)!=NULL ||
					   strstr(to,rpts_ptr[r].domain)!=NULL) {
						int a;
						for(a=0;a<rpts_ptr[r].sub_count;a++) {
							if(strstr(from,rpts_ptr[r].sub_ptr[a].address)!=NULL ||
					   		   strstr(to,rpts_ptr[r].sub_ptr[a].address)!=NULL) {
								char buffer[line_buff_size*4];
								sprintf(buffer,"%s\n%s%s%s\n",dir->d_name,subject,from,to);
								int length = rpts_ptr[r].sub_ptr[a].data_length + strlen(buffer);
								if(length>=rpts_ptr[r].sub_ptr[a].data_length) {
									rpts_ptr[r].sub_ptr[a].data_length += buffer_size+(length-rpts_ptr[r].sub_ptr[a].data_length);
									char *temp = realloc(rpts_ptr[r].sub_ptr[a].data,rpts_ptr[r].sub_ptr[a].data_length);
									if(temp==NULL) {			// this needs to be changed to have better error handling
										fprintf(stderr,"Could not increase buffer large enough to hold report data\n");
										free(file_name);
										file_name = NULL;
										return(1);
									}	
									rpts_ptr[r].sub_ptr[a].data = temp;
								}
								strcat(rpts_ptr[r].sub_ptr[a].data,buffer);
								rpts_ptr[r].sub_ptr[a].emails++;
								rpts_ptr[r].sub_ptr[a].total = rpts_ptr[r].sub_ptr[a].emails + rpts_ptr[r].sub_ptr[a].omitted;
								rpts_ptr[r].emails++;
								rpts_ptr[r].total = rpts_ptr[r].emails + rpts_ptr[r].omitted;
							}
						}
					}
				}
			}
			fclose(fp);
			fp = NULL;
		}
		free(file_name);
		file_name = NULL;
    }
    closedir(dp);
	dp = NULL;
	return(0);
}
int main(int argc, char **argv) {
	char *install_dir = NULL;
	char *omit_file = NULL;
	time_t time_now;
	time(&time_now);
	tm_ptr = localtime(&time_now);
	yday = tm_ptr->tm_yday;
	year = tm_ptr->tm_year;
	short c = 0;
	for(c=0;c<argc;c++) {
		if(strcmp(argv[c],"-a")==0 || strncmp(argv[c],"--assp=",7)==0) {
			if((strcmp(argv[c],"-a")==0 && (argc<=c+1 || strncmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--assp=")==0) {
				fprintf(stdout,"asspr requires an absolute directory path to the assp installation\n");
				return(1);
			} else {
				if(strcmp(argv[c],"-a")==0) {
					c++;
					install_dir = argv[c];
				} else if(strncasecmp(argv[c],"--assp=",7)==0)
					install_dir = argv[c]+7;
			}
		} else if(strcmp(argv[c],"-d")==0 || strncasecmp(argv[c],"--domain=",9)==0) {
			if((strcmp(argv[c],"-d")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--domain=")==0) {
				fprintf(stdout,"domain option requires a domain as an argument\n");
				return(1);
			} else {
				if(strcmp(argv[c],"-d")==0) {
					c++;
					init_rpt_ptr();
					rpts_ptr->domain = argv[c];
					rpts = 1;
				} else if(strncasecmp(argv[c],"--domain=",9)==0) {
					init_rpt_ptr();
					rpts_ptr->domain = argv[c]+9;
					rpts = 1;
				}
			}
		} else if(strcmp(argv[c],"-e")==0 || strncasecmp(argv[c],"--email-address=",16)==0) {
			if((strcmp(argv[c],"-e")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--email-address=")==0) {
				fprintf(stdout,"email address option requires a email address as an argument\n");
				return(1);
			} else {
				if(rpts_ptr==NULL)
					init_rpt_ptr();
				if(strcmp(argv[c],"-e")==0) {
					c++;
					rpts_ptr->domain = strchr(argv[c],'@')+1;
					rpts = 1;
					rpts_ptr->sub_ptr = calloc(1,sizeof(struct sub_report));
					init_sub_ptr(rpts_ptr->sub_ptr);
					rpts_ptr->sub_ptr->address = argv[c];
					rpts_ptr->sub_count++;

				} else if(strncasecmp(argv[c],"--email-address=",16)==0) {
					rpts_ptr->domain = strchr(argv[c],'@')+1;
					rpts = 1;
					rpts_ptr->sub_ptr = calloc(1,sizeof(struct sub_report));
					init_sub_ptr(rpts_ptr->sub_ptr);
					rpts_ptr->sub_ptr->address = argv[c]+16;
					rpts_ptr->sub_count++;
				}
			}
		} else if(strcmp(argv[c],"-n")==0 || strncasecmp(argv[c],"--notspam",9)==0) {
			dirs_length++;
			char **temp = realloc(dirs,sizeof(char**)*dirs_length);
			if(temp==NULL) {
				fprintf(stderr,"Could not increase directory buffer large enough to hold all directories\n");
				return(1);
			}
			dirs = temp;
			dirs[dirs_length-1] = "notspam/";
		} else if(strcmp(argv[c],"-o")==0 || strncmp(argv[c],"--omit-file=",12)==0) {
			if((strcmp(argv[c],"-o")==0 && (argc<=c+1 || strncmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--omit-file=")==0) {
				fprintf(stdout,"absolute path to a file containing subject strings to be omitted from report\n");
				return(1);
			} else {
				if(strcmp(argv[c],"-o")==0) {
					c++;
					omit_file = argv[c];
				} else if(strncasecmp(argv[c],"--omit-file=",12)==0)
					omit_file = argv[c]+12;
				if(omit_file!=NULL) {
					FILE *omit_file_ptr;
					if((omit_file_ptr = fopen(omit_file,"r"))==NULL) {
						fprintf(stderr,"Could open for omit file for reading\n");
						return(1);
					}
					char *line = calloc(line_buff_size+1,sizeof(char));
					while(fgets(line,line_buff_size,omit_file_ptr)!=NULL) {
						if(strncmp(line,"\n",1)) {
							char **temp = realloc(omit,sizeof(char**)*(omit_length+1));
							if(temp==NULL) {
								fprintf(stderr,"Could not increase buffer large enough to hold all local omit");
								return(1);
							}
							omit = temp;
							omit[omit_length] = calloc(strlen(line),sizeof(char));
							strncpy(omit[omit_length],line,strlen(line)-1);
							omit_length++;
						}
						memset(line,'\0',line_buff_size);
					}
					free(line);
					line = NULL;
					fclose(omit_file_ptr);
					omit_file_ptr = NULL;
				}
			}
		} else if(strcmp(argv[c],"-s")==0 || strncasecmp(argv[c],"--spam",9)==0) {
			dirs_length++;
			char **temp = realloc(dirs,sizeof(char**)*dirs_length);
			if(temp==NULL) {
				fprintf(stderr,"Could not increase directory buffer large enough to hold all directories\n");
				return(1);
			}
			dirs = temp;
			dirs[dirs_length-1] = "spam/";
		} else if(strcmp(argv[c],"-v")==0 || strncasecmp(argv[c],"--viruses",9)==0) {
			dirs_length++;
			char **temp = realloc(dirs,sizeof(char**)*dirs_length);
			if(temp==NULL) {
				fprintf(stderr,"Could not increase directory buffer large enough to hold all directories\n");
				return(1);
			}
			dirs = temp;
			dirs[dirs_length-1] = "viruses/";
		} else if(strcmp(argv[c],"-z")==0 || strncasecmp(argv[c],"--zero",9)==0) {
			include_zero = 1;
		} else if(strcmp(argv[c],"-D")==0 || strncasecmp(argv[c],"--days=",7)==0) {
			if((strcmp(argv[c],"-D")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--days=")==0) {
				fprintf(stdout,"days option requires a number as an argument\n");
				return(1);
			} else {
				short days = -1;
				if(strcmp(argv[c],"-D")==0) {
					c++;
					days = atoi(argv[c]);
				} else if(strncasecmp(argv[c],"--days=",7)==0)
					days = atoi(argv[c]+7);
				if(days>1)
					yday-=days;
				else if(days==0)
					yday = 0;
			}
		} else if(strcmp(argv[c],"-E")==0 || strncasecmp(argv[c],"--end-date=",11)==0) {
			if((strcmp(argv[c],"-E")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--end-date=")==0) {
				fprintf(stdout,"end date option requires a date as an argument\n");
				return(1);
			} else {
				hour = tm_ptr->tm_hour;
				fprintf(stdout,"end date option has not been implemented.\n Please contact support@obsidian-studios.com if you are interested in this feature\n");
				return(0);
			}
		} else if(strcmp(argv[c],"-H")==0 || strncasecmp(argv[c],"--hours=",8)==0) {
			if((strcmp(argv[c],"-H")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--hours=")==0) {
				fprintf(stdout,"hours option requires a number as an argument\n");
				return(1);
			} else {
				hour = tm_ptr->tm_hour;
				fprintf(stdout,"hours option has not been implemented.\n Please contact support@obsidian-studios.com if you are interested in this feature\n");
				return(0);
			}
		} else if(strcmp(argv[c],"-M")==0 || strncasecmp(argv[c],"--minutes=",10)==0) {
			if((strcmp(argv[c],"-M")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--minutes=")==0) {
				fprintf(stdout,"minutes option requires a number as an argument\n");
				return(1);
			} else {
				minute = tm_ptr->tm_min;
				fprintf(stdout,"minutes option has not been implemented.\n Please contact support@obsidian-studios.com if you are interested in this feature\n");
				return(0);
			}
		} else if(strcmp(argv[c],"-S")==0 || strncasecmp(argv[c],"--start-date=",13)==0) {
			if((strcmp(argv[c],"-S")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--start-date=")==0) {
				fprintf(stdout,"start date option requires a date as an argument\n");
				return(1);
			} else {
				hour = tm_ptr->tm_hour;
				fprintf(stdout,"start date option has not been implemented.\n Please contact support@obsidian-studios.com if you are interested in this feature\n");
				return(0);
			}
		} else if(strcmp(argv[c],"-Y")==0 || strncasecmp(argv[c],"--years=",8)==0) {
			if((strcmp(argv[c],"-Y")==0 && (argc<=c+1 || strncasecmp(argv[c+1],"-",1)==0)) ||
			   strcmp(argv[c],"--years=")==0) {
				fprintf(stdout,"year option requires a number as an argument\n");
				return(1);
			} else {
				short years = -1;
				if(strcmp(argv[c],"-Y")==0) {
					c++;
					years = atoi(argv[c]);
				} else if(strncasecmp(argv[c],"--years=",8)==0)
					years = atoi(argv[c]+8);
				if(years>1)
					yday-=years;
				else if(years==0)
					yday = 0;
			}
		} else if(strcmp(argv[c],"--help")==0) {
			fprintf(stdout,"Usage: asspr [OPTION]...\n"\
						   "Creates a report of all emails in ASSP's various directories.\n"\
						   "\n"\
						   "  -a,  --assp=/path/to/assp/\n"\
						   "                            location of ASSP\n"\
						   "  -d,  --domain=domain.com  report on this domain only\n"\
						   "  -e,  --email-address=email@domain.com\n"\
						   "                            report on this email address only\n"\
						   "  -n,  --notspam            include contents of the notspam folder in report\n"\
						   "  -o,  --omit-file=/path/to/omit-file\n"\
						   "                            absolute path to a file containing strings in\n"\
						   "                            subjects of emails to be omitted\n"\
						   "  -s,  --spam               include contents of the spam folder in report\n"\
						   "  -v,  --viruses            include contents of the viruses folder in report\n"\
						   "  -D,  --days               number of days to include in report, default is\n"\
						   "                            1 day, set to 0 for all.\n"\
						   "  -E,  --end-date           end date of the report\n"\
						   "  -H,  --hours              number of hours to include in report, default is\n"\
						   "                            start of day till time report was run at\n"\
						   "  -M,  --minutes            number of minutes to include in report\n"\
						   "  -S,  --start-date         start date of the report\n"\
						   "  -Y,  --year               year of report default is the current year, set\n"\
						   "                            to 0 for all\n"\
						   "  -z,  --zero               include addresses that received zero email\n"\
						   "       --help               display this help and exit\n"\
						   "       --version            output version information and exit\n"\
						   "\n"\
						   "Report bugs to support@obsidian-studios.com\n");
			return(0);
		} else if(strcmp(argv[c],"--version")==0) {
			fprintf(stdout,"asspr %s\n",VERSION);
			return(0);
		} else if(strcmp(argv[c],"--")==0)
			break;
	}
	if(install_dir==NULL) {
		fprintf(stdout,"ASSP installation directory not specified program aborting\n");
		return(1);
	}
	if(install_dir!=NULL && rpts_ptr==NULL) {
		FILE *file_ptr;
		char *file_name = calloc(strlen(install_dir)+15,sizeof(char));
		strcpy(file_name,install_dir);
		strcat(file_name,"locals");
		if((file_ptr = fopen(file_name,"r"))==NULL) {
			fprintf(stderr,"Could not open %s (ASSP's local domains file) for reading\n",file_name);
			return(1);
		}
		char *line = calloc(line_buff_size+1,sizeof(char));
		while(fgets(line,line_buff_size-1,file_ptr)!=NULL) {
			struct report *temp = realloc(rpts_ptr,sizeof(struct report)*(rpts+1));
			if(temp==NULL) {
				fprintf(stderr,"Could not increase buffer large enough to hold all local domains\n");
				return(1);
			}
			rpts_ptr = temp;
			rpts_ptr[rpts].domain = calloc(strlen(line),sizeof(char));
			strncpy(rpts_ptr[rpts].domain,line,strlen(line)-1);
			rpts_ptr[rpts].emails = 0;
			rpts_ptr[rpts].omitted = 0;
			rpts_ptr[rpts].total = 0;
			rpts_ptr[rpts].sub_ptr = NULL;
			rpts_ptr[rpts].sub_count = 0;
			rpts++;
			memset(line,'\0',line_buff_size);
		}
		memset(file_name,'\0',strlen(file_name));
		fclose(file_ptr);
		file_ptr = NULL;
		domain_allocated = 1;
	}
	if(rpts_ptr[0].sub_count==0) {
		FILE *file_ptr;
		char *file_name = calloc(strlen(install_dir)+15,sizeof(char));
		strcpy(file_name,install_dir);
		strcat(file_name,"localaddresses");
		if((file_ptr = fopen(file_name,"r"))==NULL) {
			fprintf(stderr,"Could not open %s (ASSP's local addresses file) for reading\n",file_name);
			return(1);
		}
		char *line = calloc(line_buff_size+1,sizeof(char));
		while(fgets(line,line_buff_size-1,file_ptr)!=NULL) {
			short r;
			for(r=0;r<rpts;r++) {
				if(strstr(line,rpts_ptr[r].domain)!=NULL) {
					struct sub_report *temp = realloc(rpts_ptr[r].sub_ptr,sizeof(struct sub_report)*(rpts_ptr[r].sub_count+1));
					if(temp==NULL) {
						fprintf(stderr,"Could not increase buffer large enough to hold all local addresses\n");
						return(1);
					}
					rpts_ptr[r].sub_ptr = temp;
					init_sub_ptr(&(rpts_ptr[r].sub_ptr[rpts_ptr[r].sub_count]));
					rpts_ptr[r].sub_ptr[rpts_ptr[r].sub_count].address = calloc(strlen(line),sizeof(char));
					strncpy(rpts_ptr[r].sub_ptr[rpts_ptr[r].sub_count].address,line,strlen(line)-1);
					rpts_ptr[r].sub_count++;
					memset(line,'\0',line_buff_size);
				}
			}
		}
		free(line);
		line = NULL;
		fclose(file_ptr);
		file_ptr = NULL;
		email_allocated = 1;
	}
	if(rpts_ptr==NULL) {
		fprintf(stdout,"domain or email not specified and/or could not be loaded from ASSPs file\n");
		return(1);
	}
	if(dirs_length==0) {
		fprintf(stdout,"Folders to report on not specified please use either/or/all -n -s -v options\n");
		return(1);
	}
	fprintf(stdout,"asspr Anti-Spam Server Proxy Report %s %s\n",VERSION,asctime(tm_ptr));
	short d;
	for(d=0;d<dirs_length;d++) {
		char *directory = calloc(strlen(install_dir)+strlen(dirs[d])+1,sizeof(char));
		strcpy(directory,install_dir);
		strcat(directory,dirs[d]);
		if(createReport(directory)==0) {
			short r;
			for(r=0;r<rpts;r++) {
				if(rpts_ptr[r].emails>0) {
					fprintf(stdout,"Domain    : %s\nDirectory : %s\nAddresses : %d\nEmails    : %d\nOmitted   : %d\nTotal     : %d\n",
									rpts_ptr[r].domain,
									directory,
									rpts_ptr[r].sub_count,
									rpts_ptr[r].emails,
									rpts_ptr[r].omitted,
									rpts_ptr[r].total);
					short a;
					for(a=0;a<rpts_ptr[r].sub_count;a++) {
						if((rpts_ptr[r].sub_ptr[a].emails>0 || include_zero==1) &&
						   rpts_ptr[r].sub_ptr[a].data!=NULL) {
							fprintf(stdout,"%sAddress   : %s\nEmails    : %d\nOmitted   : %d\nTotal     : %d\n%s\n%s%s\n\n",
											SEPARATOR,
							   				rpts_ptr[r].sub_ptr[a].address,
											rpts_ptr[r].sub_ptr[a].emails,
											rpts_ptr[r].sub_ptr[a].omitted,
											rpts_ptr[r].sub_ptr[a].total,
											SEPARATOR,
											rpts_ptr[r].sub_ptr[a].data,
											SEPARATOR);
							if(email_allocated==1 &&
							   d+1>=dirs_length) {
								free(rpts_ptr[r].sub_ptr[a].address);
								rpts_ptr[r].sub_ptr[a].address = NULL;
							}
							rpts_ptr[r].sub_ptr[a].emails = 0;
							rpts_ptr[r].sub_ptr[a].omitted = 0;
							rpts_ptr[r].sub_ptr[a].total = 0;
							free(rpts_ptr[r].sub_ptr[a].data);
							rpts_ptr[r].sub_ptr[a].data = NULL;
							rpts_ptr[r].sub_ptr[a].data_length = 0;
						}
					}
					rpts_ptr[r].emails = 0;
					rpts_ptr[r].omitted = 0;
					rpts_ptr[r].total = 0;
					if(d+1>=dirs_length) {
						if(domain_allocated==1) {
							free(rpts_ptr[r].domain);
							rpts_ptr[r].domain = NULL;
						}
						free(rpts_ptr[r].sub_ptr);
					}
				}
			}
		} else {
			fprintf(stdout,"Report could not be created\n");
			return(1);
		}
		free(directory);
		directory = NULL;
	}
	free(dirs);
	dirs = NULL;
	install_dir = NULL;
	omit_file = NULL;
	if(omit!=NULL && omit_length>0) {
		for(d = 0;d<omit_length;d++) {
			free(omit[c]);
			omit[c] = NULL;
		}
		free(omit);
	} else if(omit!=NULL)
		free(omit);
	omit = NULL;
	return (0);
}
