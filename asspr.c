/***************************************************************************
 *            asspr.c
 *
 *  Anti-Spam Server Proxy Report
 *  Copyright 2010 Obsidian-Studios, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/dir.h>
#include <sys/stat.h>
#include <sys/types.h>

#define VERSION "0.2"
#define NAME "asspr"
#define COPYRIGHT "Copyright 2010 Obsidian-Studios, Inc."
#define LICENSE "Distributed under the terms of the GNU General Public Lincense v2"
#define DISCLAIMER "This is free software: you are free to change and redistribute it.\n" \
                   "There is NO WARRANTY, to the extent permitted by law."
#define SEPARATOR "--------------------------------------------------------------\n"

char *install_dir = NULL;
char *omit_file = NULL;
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

void cleanup() {
    if(dirs)
        free(dirs);
    dirs = NULL;
    install_dir = NULL;
    omit_file = NULL;
    if(omit && omit_length>0) {
        short i;
        for(i = 0;i<omit_length;i++) {
            free(omit[i]);
            omit[i] = NULL;
        }
        free(omit);
    } else if(omit)
        free(omit);
    omit = NULL;
}

void exitError(char *msg) {
    fprintf(stderr,gettext("Error: %s\n"),msg);
    cleanup();
    _exit(EXIT_FAILURE);
}

void exitClean() {
    cleanup();
    _exit(EXIT_SUCCESS);
}

void exitNotImp(char *opt) {
    fprintf(stderr,gettext("Error: %s option has not been implemented.\n "
                           "Please contact support@obsidian-studios.com "
                           "if you are interested in this feature\n"),opt);
    cleanup();
    _exit(EXIT_FAILURE);
}

void printVersion() {
    fprintf(stdout,gettext("%s %s\n%s\n%s\n%s\n"),
                   NAME,VERSION,COPYRIGHT,LICENSE,DISCLAIMER);
}

void printHelp() {
    printVersion();
    fprintf(stdout,gettext("Usage: asspr [OPTION]...\n"\
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
                           "  -z,  --zero               include addresses that received zero email\n"\
                           "  -D,  --days               number of days to include in report, default is\n"\
                           "                            1 day, set to 0 for all.\n"\
                           "  -E,  --end-date           end date of the report\n"\
                           "  -H,  --hours              number of hours to include in report, default is\n"\
                           "                            start of day till time report was run at\n"\
                           "  -M,  --minutes            number of minutes to include in report\n"\
                           "  -S,  --start-date         start date of the report\n"\
                           "  -Y,  --year               year of report default is the current year, set\n"\
                           "                            to 0 for all\n"\
                           "       --help               display this help and exit\n"\
                           "       --version            output version information and exit\n"\
                           "\n"\
                           "Report bugs to support@obsidian-studios.com\n"));
}

void initRptPtr() {
    rpts_ptr = calloc(1,sizeof(struct report));
    rpts_ptr->domain = NULL;
    rpts_ptr->emails = 0;
    rpts_ptr->omitted = 0;
    rpts_ptr->total = 0;
    rpts_ptr->sub_count = 0;
    rpts = 0;
}

void initSubPtr(struct sub_report *sub_ptr) {
    sub_ptr->address = NULL;
    sub_ptr->emails = 0;
    sub_ptr->omitted = 0;
    sub_ptr->total = 0;
    sub_ptr->data = calloc(buffer_size,sizeof(char));
    sub_ptr->data_length = buffer_size;
}

char ** addDir(char *dir) {
    dirs_length++;
    char **temp = realloc(dirs,sizeof(char**)*dirs_length);
    if(!temp)
        exitError("Could not increase directory buffer large enough to hold all directories");
    dirs = temp;
    dirs[dirs_length-1] = dir;
}
short omitEmail(char *subject) {
    if(!omit || omit_length==0)
        return(0);
    int o;
    for(o=0;o<omit_length;o++)
        if(strstr(subject,omit[o]))
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
    if(!(dp = opendir(directory))) {
        fprintf(stderr,gettext("Could not open %s \n"),directory);
        return(1);
    }
    struct direct *dir;
    while((dir = readdir(dp))) {
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
            if(!(fp = fopen(file_name,"r"))) {
                fprintf(stderr,gettext("Could open for reading %s\n"),file_name);
                continue;
            }
            int results = 0;
            char line[line_buff_size];
            char to[line_buff_size];
            char from[line_buff_size];
            char subject[line_buff_size];
            while(fgets(line,line_buff_size-1,fp)) {
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
                            if(strstr(from,rpts_ptr[r].domain) ||
                               strstr(to,rpts_ptr[r].domain)) {
                                int a;
                                for(a=0;a<rpts_ptr[r].sub_count;a++) {
                                    if(strstr(from,rpts_ptr[r].sub_ptr[a].address) ||
                                       strstr(to,rpts_ptr[r].sub_ptr[a].address)) {
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
                    if(strstr(from,rpts_ptr[r].domain) ||
                       strstr(to,rpts_ptr[r].domain)) {
                        int a;
                        for(a=0;a<rpts_ptr[r].sub_count;a++) {
                            if(strstr(from,rpts_ptr[r].sub_ptr[a].address) ||
                               strstr(to,rpts_ptr[r].sub_ptr[a].address)) {
                                char buffer[line_buff_size*4];
                                sprintf(buffer,"%s\n%s%s%s\n",dir->d_name,subject,from,to);
                                int length = rpts_ptr[r].sub_ptr[a].data_length + strlen(buffer);
                                if(length>=rpts_ptr[r].sub_ptr[a].data_length) {
                                    rpts_ptr[r].sub_ptr[a].data_length += buffer_size+(length-rpts_ptr[r].sub_ptr[a].data_length);
                                    char *temp = realloc(rpts_ptr[r].sub_ptr[a].data,rpts_ptr[r].sub_ptr[a].data_length);
                                    if(!temp) {            // this needs to be changed to have better error handling
                                        free(file_name);
                                        file_name = NULL;
                                        exitError("Could not increase buffer large enough to hold report data");
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

    short days = -1;
    short years = -1;
    time_t time_now;
    time(&time_now);
    tm_ptr = localtime(&time_now);
    yday = tm_ptr->tm_yday;
    year = tm_ptr->tm_year;
    
    static struct option long_options[] = {
        {"assp", required_argument, NULL, 'a'},
        {"domain", required_argument, NULL, 'd'},
        {"email-address", required_argument, NULL, 'e'},
        {"help", no_argument, NULL, 0},
        {"notspam", no_argument, NULL, 'n'},
        {"omit-file", required_argument, NULL, 'o'},
        {"spam", no_argument, NULL, 's'},
        {"viruses", no_argument, NULL, 'v'},
        {"zero", no_argument, NULL, 'z'},
        {"days", required_argument, NULL, 'D'},
        {"end-date", required_argument, NULL, 'E'},
        {"hours", required_argument, NULL, 'H'},
        {"minutes", required_argument, NULL, 'M'},
        {"start-date", required_argument, NULL, 'S'},
        {"years", required_argument, NULL, 'Y'},
        {"version", no_argument, NULL, 1}
    };
    short c = 0;
    short opt = 0;
    while(opt = getopt_long(argc,argv,"a:d:e:hno:svzD:E:H:M:S:Y:",long_options,NULL), 0 <= opt) {
        switch(opt) {
            case 0 :
                printHelp();
                exitClean();
            case 1 :
                printVersion();
                exitClean();
            case 'a':
                if(!install_dir && optarg)
                    install_dir = optarg;
                else
                    exitError("Only one assp installation directory can be specified");
                break;
            case 'd' :
                initRptPtr();
                rpts_ptr->domain = optarg;
                rpts = 1;
                break;
            case 'e' :
                c++;
                rpts_ptr->domain = strchr(optarg,'@')+1;
                rpts = 1;
                rpts_ptr->sub_ptr = calloc(1,sizeof(struct sub_report));
                initSubPtr(rpts_ptr->sub_ptr);
                rpts_ptr->sub_ptr->address = optarg;
                rpts_ptr->sub_count++;
                break;
            case 'n' :
                addDir("notspam/");
                break;
            case 'o' :
                if(!omit_file && optarg) {
                    omit_file = optarg;
                } else
                    exitError("Only one omit file can be specified");
                break;
            case 's' :
                addDir("spam/");
                break;
            case 'v' :
                addDir("viruses/");
                break;
            case 'z' :
                include_zero = 1;
                break;
            case 'D' :
                days = atoi(optarg);
                if(days>1)
                    yday-=days;
                else if(days==0)
                    yday = 0;
                break;
            case 'E' :
                exitNotImp("end date");
            case 'H' :
                hour = tm_ptr->tm_hour;
                exitNotImp("hours");
            case 'M' :
                minute = tm_ptr->tm_min;
                exitNotImp("minutes");
            case 'S' :
                exitNotImp("start date");
            case 'Y' :
                years = atoi(optarg);
                if(years>1)
                    yday-=years;
                else if(years==0)
                    yday = 0;
                break;
        }
    }
    if(!install_dir)
        exitError("ASSP installation directory not specified program aborting");
    if(omit_file) {
        FILE *omit_file_ptr;
        if(!(omit_file_ptr = fopen(omit_file,"r")))
            exitError("Could open for omit file for reading\n");
        char *line = calloc(line_buff_size+1,sizeof(char));
        while(fgets(line,line_buff_size,omit_file_ptr)) {
            if(strncmp(line,"\n",1)) {
                char **temp = realloc(omit,sizeof(char**)*(omit_length+1));
                if(!temp)
                    exitError("Could not increase buffer large enough to hold all local omit");
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
    if(install_dir && !rpts_ptr) {
        FILE *file_ptr;
        char *file_name = calloc(strlen(install_dir)+15,sizeof(char));
        strcpy(file_name,install_dir);
        strcat(file_name,"locals");
        if(!(file_ptr = fopen(file_name,"r"))) {
            fprintf(stderr,gettext("Could not open %s (ASSP's local domains file) for reading\n"),file_name);
            free(file_name);
            cleanup();
            exit(EXIT_FAILURE);
        }
        char *line = calloc(line_buff_size+1,sizeof(char));
        while(fgets(line,line_buff_size-1,file_ptr)) {
            struct report *temp = realloc(rpts_ptr,sizeof(struct report)*(rpts+1));
            if(!temp)
                exitError("Could not increase buffer large enough to hold all local domains");
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
        free(file_name);
        fclose(file_ptr);
        file_ptr = NULL;
        domain_allocated = 1;
    }
    if(rpts_ptr[0].sub_count==0) {
        FILE *file_ptr;
        char *file_name = calloc(strlen(install_dir)+15,sizeof(char));
        strcpy(file_name,install_dir);
        strcat(file_name,"localaddresses");
        if(!(file_ptr = fopen(file_name,"r"))) {
            fprintf(stderr,gettext("Could not open %s (ASSP's local addresses file) for reading\n"),file_name);
            free(file_name);
            cleanup();
            exit(EXIT_FAILURE);
        }
        char *line = calloc(line_buff_size+1,sizeof(char));
        while(fgets(line,line_buff_size-1,file_ptr)) {
            short r;
            for(r=0;r<rpts;r++) {
                if(strstr(line,rpts_ptr[r].domain)) {
                    struct sub_report *temp = realloc(rpts_ptr[r].sub_ptr,sizeof(struct sub_report)*(rpts_ptr[r].sub_count+1));
                    if(!temp)
                        exitError("Could not increase buffer large enough to hold all local addresses");
                    rpts_ptr[r].sub_ptr = temp;
                    initSubPtr(&(rpts_ptr[r].sub_ptr[rpts_ptr[r].sub_count]));
                    rpts_ptr[r].sub_ptr[rpts_ptr[r].sub_count].address = calloc(strlen(line),sizeof(char));
                    strncpy(rpts_ptr[r].sub_ptr[rpts_ptr[r].sub_count].address,line,strlen(line)-1);
                    rpts_ptr[r].sub_count++;
                    memset(line,'\0',line_buff_size);
                }
            }
        }
        free(line);
        line = NULL;
        free(file_name);
        fclose(file_ptr);
        file_ptr = NULL;
        email_allocated = 1;
    }
    if(!rpts_ptr)
        exitError("Domain or email not specified and/or could not be loaded from ASSPs file");
    if(dirs_length==0)
        exitError("Folders to report on not specified please use either/or/all -n -s -v options");
    fprintf(stdout,gettext("asspr Anti-Spam Server Proxy Report %s %s\n"),VERSION,asctime(tm_ptr));
    short d;
    for(d=0;d<dirs_length;d++) {
        char *directory = calloc(strlen(install_dir)+strlen(dirs[d])+1,sizeof(char));
        strcpy(directory,install_dir);
        strcat(directory,dirs[d]);
        if(createReport(directory)==0) {
            short r;
            for(r=0;r<rpts;r++) {
                if(rpts_ptr[r].emails>0) {
                    fprintf(stdout,gettext("Domain    : %s\nDirectory : %s\n"),
                                   rpts_ptr[r].domain,
                                   directory);
                    if(rpts_ptr[r].sub_count>1)
                        fprintf(stdout,gettext("Addresses : %d\nEmails : %d\n"),
                                       rpts_ptr[r].sub_count,
                                       rpts_ptr[r].emails);
                    if(omit_length>0)
                        fprintf(stdout,gettext("Omitted   : %d\nTotal     : %d\n"),
                                       rpts_ptr[r].omitted,
                                       rpts_ptr[r].total);
                    short a;
                    for(a=0;a<rpts_ptr[r].sub_count;a++) {
                        if((rpts_ptr[r].sub_ptr[a].emails>0 || include_zero==1) &&
                           rpts_ptr[r].sub_ptr[a].data) {
                            fprintf(stdout,gettext("%sAddress   : %s\nEmails    : %d\n"),
                                           SEPARATOR,
                                           rpts_ptr[r].sub_ptr[a].address,
                                           rpts_ptr[r].sub_ptr[a].emails);
                            if(omit_length>0)
                                fprintf(stdout,gettext("Omitted   : %d\nTotal     : %d\n"),
                                               rpts_ptr[r].sub_ptr[a].omitted,
                                               rpts_ptr[r].sub_ptr[a].total);
                            fprintf(stdout,gettext("%s\n%s%s\n\n"),
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
        } else
            exitError("Report could not be created");
        free(directory);
        directory = NULL;
    }
    atexit(cleanup);
    exit(EXIT_SUCCESS);
}
