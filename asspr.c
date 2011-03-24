/***************************************************************************
 *            asspr.c
 *
 *  Anti-Spam Server Proxy Report
 *  Copyright 2011 Obsidian-Studios, Inc.
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <argp.h>
#include <sys/dir.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SEPARATOR "--------------------------------------------------------------\n"

const char *argp_program_version = "asspr, version 0.2.2";
const char *argp_program_bug_address = "support@obsidian-studios.com";
static char doc[] = "\nCopyright 2011 Obsidian-Studios, Inc.\n"
                    "Distributed under the terms of the GNU General Public Lincense v2 "
                    "This is free software: you are free to change and redistribute it. \n"
                    "There is NO WARRANTY, to the extent permitted by law.";
/* Unused arguments description */
static char args_doc[] = "";

char *install_dir = NULL;
char *omit_file = NULL;
char **dirs = NULL;
char **omit = NULL;
unsigned short dirs_length = 0;
unsigned short omit_length = 0;
unsigned short rpts = 0;
bool address_allocated = false;
bool domain_allocated = false;
bool include_zero = false;
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

void freeReport(struct report *report) {
    if(domain_allocated) {
        free(report->domain);
        report->domain = NULL;
    }
    free(report->sub_ptr);
    report->sub_ptr = NULL;
}
void freeAddress(char *address) {
    if(address_allocated) {
        free(address);
        address = NULL;
    }
}
void cleanup() {
    free(dirs);
    if(omit && omit_length) {
        short i;
        for(i=0;i<omit_length;i++)
            free(omit[i]);
    }
    free(omit);
    if(rpts_ptr && rpts) {
        short r;
        for(r=0;r<rpts;r++) {
            short a;
            for(a=0;a<rpts_ptr[r].sub_count;a++) {
                freeAddress(rpts_ptr[r].sub_ptr[a].address);
                free(rpts_ptr[r].sub_ptr[a].data);
            }
            freeReport(&rpts_ptr[r]);
        }
    }
    free(rpts_ptr);
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
    if(!omit || !omit_length)
        return(0);
    int o;
    for(o=0;o<omit_length;o++)
        if(strstr(subject,omit[o]))
            return(1);
    return(0);
}

short inDateRange(struct tm *file_tm_ptr) {
    if((!yday || yday<=file_tm_ptr->tm_yday) &&
       (!year || year<=file_tm_ptr->tm_year))
        return(1);
    else
        return(0);
}

short createReport(char *directory) {
    DIR *dp;
    if(!(dp = opendir(directory))) {
        fprintf(stderr,gettext("Could not open %s \n"),directory);
        return(0);
    }
    struct direct *dir;
    while((dir = readdir(dp))) {
        if(dir->d_ino == 0)
            continue;
        if(!strncasecmp(dir->d_name,".",1) ||
           !strncasecmp(dir->d_name,"..",2))
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
        if(inDateRange(file_tm_ptr)) {
            FILE *fp;
            if(!(fp = fopen(file_name,"r"))) {
                fprintf(stderr,gettext("Could open for reading %s\n"),file_name);
                continue;
            }
            int results = 0;
            char *line = calloc(line_buff_size,sizeof(char));
            char *to = calloc(line_buff_size,sizeof(char));
            char *from = calloc(line_buff_size,sizeof(char));
            char *subject = calloc(line_buff_size,sizeof(char));
            while(fgets(line,line_buff_size-1,fp)) {
                if(!strncasecmp(line,"From",4)) {
                    strcpy(from,line);
                    results++;
                } else if(!strncasecmp(line,"To",2)) {
                    strcpy(to,line);
                    results++;
                } else if(!strncasecmp(line,"Subject",7)) {
                    if(omitEmail(line)) {
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
                    }
                }
                memset(line,'\0',line_buff_size);
                if(results==3)
                    break;
            }
            fclose(fp);
            if(results==3) {
                int r;
                for(r=0;r<rpts;r++) {
                    if(rpts_ptr[r].domain &&
                       (strstr(from,rpts_ptr[r].domain) ||
                        strstr(to,rpts_ptr[r].domain))) {
                        int a;
                        for(a=0;a<rpts_ptr[r].sub_count;a++) {
                            if(rpts_ptr[r].sub_ptr[a].address &&
                               (strstr(from,rpts_ptr[r].sub_ptr[a].address) ||
                                strstr(to,rpts_ptr[r].sub_ptr[a].address))) {
                                char *buffer = calloc(line_buff_size*4,sizeof(char));
                                sprintf(buffer,"%s\n%s%s%s\n",dir->d_name,subject,from,to);
                                int length = rpts_ptr[r].sub_ptr[a].data_length + strlen(buffer);
                                if(length>=rpts_ptr[r].sub_ptr[a].data_length) {
                                    rpts_ptr[r].sub_ptr[a].data_length += buffer_size+(length-rpts_ptr[r].sub_ptr[a].data_length);
                                    char *temp = realloc(rpts_ptr[r].sub_ptr[a].data,rpts_ptr[r].sub_ptr[a].data_length);
                                    if(!temp) {            // this needs to be changed to have better error handling
                                        free(line);
                                        free(to);
                                        free(from);
                                        free(subject);
                                        free(buffer);
                                        exitError("Could not increase buffer large enough to hold report data");
                                    }
                                    rpts_ptr[r].sub_ptr[a].data = temp;
                                }
                                strcat(rpts_ptr[r].sub_ptr[a].data,buffer);
                                rpts_ptr[r].sub_ptr[a].emails++;
                                rpts_ptr[r].sub_ptr[a].total = rpts_ptr[r].sub_ptr[a].emails + rpts_ptr[r].sub_ptr[a].omitted;
                                rpts_ptr[r].emails++;
                                rpts_ptr[r].total = rpts_ptr[r].emails + rpts_ptr[r].omitted;
                                free(buffer);
                            }
                        }
                    }
                }
            }
            free(line);
            free(to);
            free(from);
            free(subject);
        }
        free(file_name);
    }
    closedir(dp);
    return(1);
}

static struct argp_option options[] = {
    {"assp", 'a', "/path/to/assp/", 0, "location of ASSP"},
    {"discarded", 'c', 0, 0, "include contents of the discarded folder in report"},
    {"domain", 'd', "domain.com", 0, "report on this domain only"},
    {"email-address", 'e', "email@domain.com", 0, "report on this email address only"},
    {"notspam", 'n', 0, 0, "include contents of the notspam folder in report"},
    {"omit-file", 'o', "/path/to/omit-file", 0, "absolute path to a file containing strings in subjects of emails to be omitted"},
    {"spam", 's', 0, 0, "include contents of the spam folder in report"},
    {"viruses", 'v', 0, 0, "include contents of the viruses folder in report"},
    {"zero", 'z', 0, 0, "include addresses that received zero email"},
    {"days", 'D', "NUM", 0, "number of days to include in report, default is 1 day, set to 0 for all"},
    {"end-date", 'E', "DATE", 0, "end date of the report"},
    {"hours", 'H', "NUM", 0, "number of hours to include in report, default is start of day till time report was run at"},
    {"minutes", 'M', "NUM", 0, "number of minutes to include in report"},
    {"start-date", 'S', "DATE", 0, "start date of the report"},
    {"years", 'Y', "YEAR", 0, "year of report default is the current year, set to 0 for all"}
};

struct args {
    short c;
    short days;
    short years;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct args *pargs = state->input;
    switch(key) {
        case 'a':
            if(!install_dir && arg)
                install_dir = arg;
            else
                exitError("Only one assp installation directory can be specified");
            break;
        case 'c' :
            addDir("discarded/");
            break;
        case 'd' :
            initRptPtr();
            rpts_ptr->domain = arg;
            rpts = 1;
            break;
        case 'e' :
            pargs->c++;
            initRptPtr();
            rpts_ptr->domain = strchr(arg,'@')+1;
            rpts = 1;
            rpts_ptr->sub_ptr = calloc(1,sizeof(struct sub_report));
            initSubPtr(rpts_ptr->sub_ptr);
            rpts_ptr->sub_ptr->address = arg;
            rpts_ptr->sub_count++;
            break;
        case 'n' :
            addDir("notspam/");
            break;
        case 'o' :
            if(!omit_file && arg)
                omit_file = arg;
            else
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
            pargs->days = atoi(arg);
            if(pargs->days>1)
                yday-=pargs->days;
            else if(!pargs->days)
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
            pargs->years = atoi(arg);
            if(pargs->years>1)
                yday-=pargs->years;
            else if(!pargs->years)
                yday = 0;
            break;
    }
    return(0);
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char **argv) {
    struct args args;
    args.c = 0;
    args.days = -1;
    args.years = -1;
    
    time_t time_now;
    time(&time_now);
    tm_ptr = localtime(&time_now);
    yday = tm_ptr->tm_yday;
    year = tm_ptr->tm_year;
    
    argp_parse(&argp, argc, argv, 0, 0, &args);

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
        fclose(omit_file_ptr);
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
        free(line);
        free(file_name);
        fclose(file_ptr);
        domain_allocated = true;
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
        free(file_name);
        fclose(file_ptr);
        address_allocated = true;
    }
    if(!rpts_ptr)
        exitError("Domain or email not specified and/or could not be loaded from ASSPs file");
    if(!dirs_length)
        exitError("Folders to report on not specified please use either/or/all -n -s -v options");
    fprintf(stdout,gettext("Anti-Spam Server Proxy Report %s %s\n"),argp_program_version,asctime(tm_ptr));
    short d;
    for(d=0;d<dirs_length;d++) {
        char *directory = calloc(strlen(install_dir)+strlen(dirs[d])+1,sizeof(char));
        strcpy(directory,install_dir);
        strcat(directory,dirs[d]);
        if(createReport(directory)) {
            short r;
            for(r=0;r<rpts;r++) {
                if(rpts_ptr[r].emails) {
                    fprintf(stdout,gettext("Domain    : %s\nDirectory : %s\n"),
                                   rpts_ptr[r].domain,
                                   directory);
                    if(rpts_ptr[r].sub_count>1)
                        fprintf(stdout,gettext("Addresses : %d\nEmails : %d\n"),
                                       rpts_ptr[r].sub_count,
                                       rpts_ptr[r].emails);
                    if(omit_length)
                        fprintf(stdout,gettext("Omitted   : %d\nTotal     : %d\n"),
                                       rpts_ptr[r].omitted,
                                       rpts_ptr[r].total);
                    short a;
                    for(a=0;a<rpts_ptr[r].sub_count;a++) {
                        if((rpts_ptr[r].sub_ptr[a].emails || include_zero) &&
                           rpts_ptr[r].sub_ptr[a].data) {
                            fprintf(stdout,gettext("%sAddress   : %s\nEmails    : %d\n"),
                                           SEPARATOR,
                                           rpts_ptr[r].sub_ptr[a].address,
                                           rpts_ptr[r].sub_ptr[a].emails);
                            if(omit_length)
                                fprintf(stdout,gettext("Omitted   : %d\nTotal     : %d\n"),
                                               rpts_ptr[r].sub_ptr[a].omitted,
                                               rpts_ptr[r].sub_ptr[a].total);
                            fprintf(stdout,gettext("%s\n%s%s\n\n"),
                                           SEPARATOR,
                                           rpts_ptr[r].sub_ptr[a].data,
                                           SEPARATOR);
                            if(d+1>=dirs_length) {
                                freeAddress(rpts_ptr[r].sub_ptr[a].address);
                                free(rpts_ptr[r].sub_ptr[a].data);
                                rpts_ptr[r].sub_ptr[a].data = NULL;
                                rpts_ptr[r].sub_ptr[a].data_length = 0;
                            } else
                                memset(rpts_ptr[r].sub_ptr[a].data,'\0',rpts_ptr[r].sub_ptr[a].data_length);
                            rpts_ptr[r].sub_ptr[a].emails = 0;
                            rpts_ptr[r].sub_ptr[a].omitted = 0;
                            rpts_ptr[r].sub_ptr[a].total = 0;
                        }
                    }
                    rpts_ptr[r].emails = 0;
                    rpts_ptr[r].omitted = 0;
                    rpts_ptr[r].total = 0;
                    if(d+1>=dirs_length)
                        freeReport(&rpts_ptr[r]);
                }
            }
        } else
            exitError("Report could not be created");
        free(directory);
    }
    atexit(cleanup);
    exit(EXIT_SUCCESS);
}
