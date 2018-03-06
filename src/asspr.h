/***************************************************************************
 *  asspr.h
 *
 *  Anti-Spam Server Proxy Report
 *  Copyright 2006-2018 Obsidian-Studios, Inc.
 *  Author William L. Thomson Jr.
 *         wlt@obsidian-studios.com
 ****************************************************************************/

/*
 *  This file is part of asspr.
 *
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

#define SEPARATOR "--------------------------------------------------------------\n"

#include <stdbool.h>
#include <time.h>
#include <argp.h>

/**
 * Program arguments struct
 */
struct args {
    short c;
    short days;
    short years;
};

/**
 * GNU argp options struct
 */
static struct argp_option options[] = {
    {0,0,0,0,"ASSP Paths:"},
    {"assp", 'a', "/path/to/assp/", 0, "location of ASSP"},
    {"config", 'C', "/path/to/config/", 0, "location of ASSP configuration files"},
    {0,0,0,0,"Report Options:", 2},
    {"discarded", 'c', 0, 0, "include contents of the discarded folder in report", 2},
    {"domain", 'd', "domain.com", 0, "report on this domain only", 2},
    {"email-address", 'e', "email@domain.com", 0, "report on this email address only", 2},
    {"notspam", 'n', 0, 0, "include contents of the notspam folder in report", 2},
    {"omit-file", 'o', "/path/to/omit-file", 0, "absolute path to a file containing strings in subjects of emails to be omitted", 2},
    {"spam", 's', 0, 0, "include contents of the spam folder in report", 2},
    {"viruses", 'v', 0, 0, "include contents of the viruses folder in report", 2},
    {"zero", 'z', 0, 0, "include addresses that received zero email", 2},
    {"days", 'D', "NUM", 0, "number of days to include in report, default is 1 day, set to 0 for all", 2},
    {"end-date", 'E', "DATE", 0, "end date of the report", 2},
    {"hours", 'H', "NUM", 0, "number of hours to include in report, default is start of day till time report was run at", 2},
    {"minutes", 'M', "NUM", 0, "number of minutes to include in report", 2},
    {"start-date", 'S', "DATE", 0, "start date of the report", 2},
    {"years", 'Y', "YEAR", 0, "year of report default is the current year, set to 0 for all", 2},
    {0,0,0,0,"GNU Options:", 3},
    {0}
};

/**
 * Report struct
 */
struct report {
    char *domain;
    bool domain_allocated;
    unsigned short emails;
    unsigned short omitted;
    unsigned short total;
    struct sub_report *sub_ptr;
    unsigned short sub_count;
};

/**
 * Sub Report struct
 */
struct sub_report {
    char *address;
    bool address_allocated;
    unsigned short emails;
    unsigned short omitted;
    unsigned short total;
    char *data;
    unsigned int data_length;
};

/**
 * Variable to hold the main report pointer
 */
extern struct report *rpts_ptr;

/**
 * Add a directory to the report
 *
 * @param dir a string containing a directory to add to the report
 */
char ** addDir(char *dir);

/**
 * Cleanup before exit, free allocated memory
 *
 * @param argc argument count from main
 * @param argv argument value array from main
 */
void asspr(int argc, char **argv);

/**
 * Cleanup before exit, free allocated memory
 */
void cleanup();

/**
 * Create a report
 *
 * @param directory a string containing a directory to create a report for
 * @return short, 1 for success, 0 for failure. The short must NOT be freed!
 */
short createReport(char *directory);

/**
 * Exit clean/normally
 */
void exitClean();

/**
 * Exit with an error code and message
 *  
 * @param msg a string containing an error message
 */
void exitError(char *msg);

/**
 * Exit with an error code and not implemented message
 *  
 * @param opt a string containing an option not implemented
 */
void exitNotImp(char *opt);

/**
 * Frees the allocated memory used by an array of report structs
 *
 * @param report a pointer to an array of report structs
 */
void freeReport(struct report *report);

/**
 * Frees the allocated memory used by an address in a sub report struct
 *
 * @param sub_ptr a pointer to a sub report struct
 */
void freeAddress(struct sub_report *sub_ptr);

/**
 * Get the config directory
 *
 * @return a string containing the value. The string must be freed!
 */
char * getConfigDir();

/**
 * Check if a file is in the date range of the report
 *
 * @param file_tm_ptr a pointer to a file's time struct
 * @return short, 1 for success, 0 for failure. The short must NOT be freed!
 */
short inDateRange(struct tm *file_tm_ptr);

/**
 * Initialize main rpts_ptr array
 */
void initRptPtr();

/**
 * Initialize a sub_ptr
 * 
 * @param sub_ptr a pointer to a sub report struct
 */
void initSubPtr(struct sub_report *sub_ptr);

/**
 * Load omit file contents into variable array
 */
void loadOmitFile();

/**
 * Check if an email should be omitted from the report
 *
 * @param subject a string containing an email's subject
 * @return short, 1 for success, 0 for failure. The short must NOT be freed!
 */
short omitEmail(char *subject);
