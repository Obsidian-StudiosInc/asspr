/***************************************************************************
 *            asspr.c
 *
 *  Anti-Spam Server Proxy Report
 *  Copyright 2006-2018 Obsidian-Studios, Inc.
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

#include "asspr.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/dir.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(x) gettext(x)
#else
# define _(x) (x)
#endif

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
static char doc[] = "\nCopyright 2006-2018 Obsidian-Studios, Inc.\n"
                    "Distributed under the terms of the GNU General Public License v2 "
                    "This is free software: you are free to change and redistribute it. \n"
                    "There is NO WARRANTY, to the extent permitted by law.";
/* Unused arguments description */
static char args_doc[] = "";

char *install_dir = NULL;
char *config_dir = NULL;
char *omit_file = NULL;
char **dirs = NULL;
char **omit = NULL;
unsigned short dir_buffer_length = 20;
unsigned short dirs_length = 0;
unsigned short omit_length = 0;
unsigned short rpts = 0;
bool include_zero = false;
int yday;
int year;
int hour;
int minute;
unsigned short buffer_size = sizeof(char)*2048;
unsigned short line_buff_size = sizeof(char)*256;
struct tm *tm_ptr = NULL;
struct report *rpts_ptr = NULL;

/**
 * Get the config directory
 *
 * @return a string containing the value. The string must be freed!
 */
char * getConfigDir() {
    char *file_name = NULL;
    if(config_dir) {
        file_name = calloc(strlen(config_dir)+dir_buffer_length,sizeof(char));
        strncpy(file_name,config_dir,strlen(config_dir)+1);
    } else {
        file_name = calloc(strlen(install_dir)+dir_buffer_length,sizeof(char));
        strncpy(file_name,install_dir,strlen(install_dir)+1);
    }
    return(file_name);
}

/**
 * Frees the allocated memory used by an array of report structs
 *
 * @param report a pointer to an array of report structs
 */
void freeReport(struct report *report) {
    if(report->domain_allocated) {
        short i;
        for(i=0;i<report->sub_count;i++) {
            freeAddress(&(report->sub_ptr[i]));
            free(report->sub_ptr[i].data);
        }
        free(report->domain);
        report->domain = NULL;
        report->domain_allocated = false;
    }
    free(report->sub_ptr);
    report->sub_ptr = NULL;
}

/**
 * Frees the allocated memory used by an address in a sub report struct
 *
 * @param sub_ptr a pointer to a sub report struct
 */
void freeAddress(struct sub_report *sub_ptr) {
    if(sub_ptr->address_allocated) {
        free(sub_ptr->address);
        sub_ptr->address = NULL;
        sub_ptr->address_allocated = false;
    }
}

/**
 * Cleanup before exit, free allocated memory
 */
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
        for(r=0;r<rpts;r++)
            freeReport(&rpts_ptr[r]);
    }
    free(rpts_ptr);
}

/**
 * Exit with an error code and message
 *  
 * @param msg a string containing an error message
 */
void exitError(char *msg) {
    fprintf(stderr,_("Error: %s\n"),msg);
    cleanup();
    exit(EXIT_FAILURE);
}

/**
 * Exit with an error code and not implemented message
 *  
 * @param opt a string containing an option not implemented
 */
void errorNotImp(char *opt) {
    fprintf(stderr,_("Error: %s option has not been implemented.\n "
                           "Please contact support@obsidian-studios.com "
                           "if you are interested in this feature\n"),opt);
}

/**
 * Initialize main rpts_ptr array
 */
void initRptPtr() {
    rpts_ptr = calloc(1,sizeof(struct report));
    rpts_ptr->domain = NULL;
    rpts_ptr->domain_allocated = false;
    rpts_ptr->emails = 0;
    rpts_ptr->omitted = 0;
    rpts_ptr->total = 0;
    rpts_ptr->sub_count = 0;
    rpts = 0;
}

/**
 * Initialize a sub_ptr
 * 
 * @param sub_ptr a pointer to a sub report struct
 */
void initSubPtr(struct sub_report *sub_ptr) {
    sub_ptr->address = NULL;
    sub_ptr->address_allocated = false;
    sub_ptr->emails = 0;
    sub_ptr->omitted = 0;
    sub_ptr->total = 0;
    sub_ptr->data = calloc(buffer_size,sizeof(char));
    sub_ptr->data_length = buffer_size;
}

/**
 * Add a directory to the report
 *
 * @param dir a string containing a directory to add to the report
 */
char ** addDir(char *dir) {
    dirs_length++;
    char **temp = realloc(dirs,sizeof(char*)*dirs_length);
    if(!temp)
        exitError("Could not increase directory buffer large enough to hold all directories");
    dirs = temp;
    dirs[dirs_length-1] = dir;
    return(dirs);
}

/**
 * Load local addresses file contents into variable array
 */
void loadLocalAdressses() {
    if(rpts_ptr[0].sub_count==0) {
        FILE *file_ptr;
        char *file_name = getConfigDir();
        strncat(file_name,"localaddresses.txt",19);
        if(!(file_ptr = fopen(file_name,"r"))) {
            fprintf(stderr,_("Could not open %s (ASSP's local addresses file) for reading\n"),file_name);
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
                    rpts_ptr[r].sub_ptr[rpts_ptr[r].sub_count].address_allocated = true;
                    rpts_ptr[r].sub_count++;
                    memset(line,'\0',line_buff_size);
                }
            }
        }
        free(line);
        free(file_name);
        fclose(file_ptr);
    }
}

/**
 * Load local domains file contents into variable array
 */
void loadLocalDomains() {
    if(install_dir && !rpts_ptr) {
        FILE *file_ptr;
        char *file_name = getConfigDir();
        strncat(file_name,"localdomains.txt",17);
        if(!(file_ptr = fopen(file_name,"r"))) {
            fprintf(stderr,_("Could not open %s (ASSP's local domains file) for reading\n"),file_name);
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
            rpts_ptr[rpts].domain_allocated = true;
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
    }
}

/**
 * Load omit file contents into variable array
 */
void loadOmitFile() {
    if(omit_file) {
        FILE *omit_file_ptr;
        if(!(omit_file_ptr = fopen(omit_file,"r")))
            exitError("Could open for omit file for reading\n");
        char *line = calloc(line_buff_size+1,sizeof(char));
        while(fgets(line,line_buff_size,omit_file_ptr)) {
            if(strncmp(line,"\n",1)) {
                char **temp = realloc(omit,sizeof(char*)*(omit_length+1));
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
}

/**
 * Check if an email should be omitted from the report
 *
 * @param subject a string containing an email's subject
 * @return short, 1 for success, 0 for failure. The short must NOT be freed!
 */
short omitEmail(char *subject) {
    if(!omit || !omit_length)
        return(0);
    int o;
    for(o=0;o<omit_length;o++)
        if(strstr(subject,omit[o]))
            return(1);
    return(0);
}

/**
 * Check if a file is in the date range of the report
 *
 * @param file_tm_ptr a pointer to a file's time struct
 * @return short, 1 for success, 0 for failure. The short must NOT be freed!
 */
short inDateRange(struct tm *file_tm_ptr) {
    if((!yday || yday<=file_tm_ptr->tm_yday) &&
       (!year || year<=file_tm_ptr->tm_year))
        return(1);
    else
        return(0);
}

/**
 * Create a report
 *
 * @param directory a string containing a directory to create a report for
 * @return short, 1 for success, 0 for failure. The short must NOT be freed!
 */
short createReport(char *directory) {
    DIR *dp;
    if(!(dp = opendir(directory))) {
        fprintf(stderr,_("Could not open %s \n"),directory);
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
        strncpy(file_name,directory,strlen(directory)+1);
        strncat(file_name,dir->d_name,strlen(dir->d_name)+1);
        FILE *fp;
        if(!(fp = fopen(file_name,"r"))) {
            fprintf(stderr,_("Could not open for reading %s\n"),file_name);
            free(file_name);
            continue;
        }
        if(flock(fileno(fp), LOCK_SH)==-1) {
            fprintf(stderr,_("Could not obtain lock %s\n"),file_name);
            fclose(fp);
            free(file_name);
            continue;
        }
        struct stat buf;
        if(fstat(fileno(fp),&buf)==-1) {
            fprintf(stderr,_("Could not stat %s\n"),file_name);
            flock(fileno(fp), LOCK_UN);
            fclose(fp);
            free(file_name);
            continue;
        }
        time_t file_time = buf.st_mtime;
        struct tm *file_tm_ptr = localtime(&file_time);
        if(inDateRange(file_tm_ptr)) {
            int results = 0;
            char *line = calloc(line_buff_size,sizeof(char));
            char *to = calloc(line_buff_size,sizeof(char));
            char *from = calloc(line_buff_size,sizeof(char));
            char *subject = calloc(line_buff_size,sizeof(char));
            while(fgets(line,line_buff_size-1,fp)) {
                if(!strncasecmp(line,"From",4)) {
                    strncpy(from,line,strlen(line)+1);
                    results++;
                } else if(!strncasecmp(line,"To",2)) {
                    strncpy(to,line,strlen(line)+1);
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
                        strncpy(subject,line,strlen(line)+1);
                        results++;
                    }
                }
                memset(line,'\0',line_buff_size);
                if(results==3)
                    break;
            }
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
                                int buffer_size = line_buff_size*4;
                                char *buffer = calloc(buffer_size,sizeof(char));
                                if(buffer) {
                                    snprintf(buffer,buffer_size-1,"%s\n%s%s%s\n",dir->d_name,subject,from,to);
                                    int length = rpts_ptr[r].sub_ptr[a].data_length + strlen(buffer);
                                    if(length>=rpts_ptr[r].sub_ptr[a].data_length) {
                                        rpts_ptr[r].sub_ptr[a].data_length += buffer_size+(length-rpts_ptr[r].sub_ptr[a].data_length);
                                        char *temp = realloc(rpts_ptr[r].sub_ptr[a].data,rpts_ptr[r].sub_ptr[a].data_length);
                                        if(!temp) {
                                           free(buffer);
                                           goto FREE_LINE;
                                        }
                                        rpts_ptr[r].sub_ptr[a].data = temp;
                                    }
                                    strncat(rpts_ptr[r].sub_ptr[a].data,buffer,strlen(buffer)+1);
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
            }
            FREE_LINE:
            free(line);
            free(to);
            free(from);
            free(subject);
        }
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        free(file_name);
    }
    closedir(dp);
    return(1);
}

/**
 * Print report
 *
 * @param d the directory index of directories pointer array
 * @param r the report index of report struct pointer array
 */
void printReport(char *directory, short d, short r) {
    fprintf(stdout,_("Domain    : %s\nDirectory : %s\n"),
                   rpts_ptr[r].domain,
                   directory);
    if(rpts_ptr[r].sub_count>1)
        fprintf(stdout,_("Addresses : %d\nEmails : %d\n"),
                       rpts_ptr[r].sub_count,
                       rpts_ptr[r].emails);
    if(omit_length)
        fprintf(stdout,_("Omitted   : %d\nTotal     : %d\n"),
                       rpts_ptr[r].omitted,
                       rpts_ptr[r].total);
    short a;
    for(a=0;a<rpts_ptr[r].sub_count;a++) {
        if((rpts_ptr[r].sub_ptr[a].emails || include_zero) &&
           rpts_ptr[r].sub_ptr[a].data) {
            fprintf(stdout,_("%sAddress   : %s\nEmails    : %d\n"),
                           SEPARATOR,
                           rpts_ptr[r].sub_ptr[a].address,
                           rpts_ptr[r].sub_ptr[a].emails);
            if(omit_length)
                fprintf(stdout,_("Omitted   : %d\nTotal     : %d\n"),
                               rpts_ptr[r].sub_ptr[a].omitted,
                               rpts_ptr[r].sub_ptr[a].total);
            fprintf(stdout,_("%s\n%s%s\n\n"),
                           SEPARATOR,
                           rpts_ptr[r].sub_ptr[a].data,
                           SEPARATOR);
            if(d+1>=dirs_length) {
                freeAddress(&(rpts_ptr[r].sub_ptr[a]));
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
        case 'C':
            if(!config_dir && arg)
                config_dir = arg;
            else
                exitError("Only one assp configuration directory can be specified");
            break;
        case 'D' :
            pargs->days = atoi(arg);
            if(pargs->days>1)
                yday-=pargs->days;
            else if(!pargs->days)
                yday = 0;
            break;
        case 'E' :
            errorNotImp("end date");
            return(0);
        case 'H' :
            hour = tm_ptr->tm_hour;
            errorNotImp("hours");
            return(0);
        case 'M' :
            minute = tm_ptr->tm_min;
            errorNotImp("minutes");
            return(0);
        case 'S' :
            errorNotImp("start date");
            return(0);
        case 'Y' :
            pargs->years = atoi(arg);
            if(pargs->years>1)
                yday-=pargs->years;
            else if(!pargs->years)
                yday = 0;
            break;
        default:
            return ARGP_ERR_UNKNOWN;

    }
    return(0);
}

static struct argp argp = { options, parse_opt, args_doc, doc };

void asspr(int argc, char **argv) {
    struct args args;
    args.c = 0;
    args.days = -1;
    args.years = -1;

    char time_str[line_buff_size];
    time_t time_now;
    time(&time_now);
    tm_ptr = localtime(&time_now);
    strftime(time_str, line_buff_size, "%a %b %d %T %y", tm_ptr);
    yday = tm_ptr->tm_yday;
    year = tm_ptr->tm_year;

    argp_parse(&argp, argc, argv, ARGP_NO_EXIT, 0, &args);

    if(!install_dir)
        exitError("ASSP installation directory not specified program aborting");
    loadOmitFile();
    loadLocalDomains();
    loadLocalAdressses();
    if(!rpts_ptr)
        exitError("Domain or email not specified and/or could not be loaded from ASSPs file");
    if(!dirs_length)
        exitError("Folders to report on not specified please use either/or/all -n -s -v options");
    fprintf(stdout,
            _("Anti-Spam Server Proxy Report %s %s\n"),
            argp_program_version,
            time_str);
    short d;
    short r;
    for(d=0;d<dirs_length;d++) {
        char *directory = calloc(strlen(install_dir)+strlen(dirs[d])+1,sizeof(char));
        strncpy(directory,install_dir,strlen(install_dir)+1);
        strncat(directory,dirs[d],strlen(dirs[d])+1);
        if(createReport(directory)) {
            for(r=0;r<rpts;r++) {
                if(rpts_ptr[r].emails) {
                    printReport(directory,d,r);
                }
            }
        } else
            exitError("Report could not be created");
        free(directory);
    }
}
