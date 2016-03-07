/***************************************************************************
 *  asspr.h
 *
 *  Anti-Spam Server Proxy Report
 *  Copyright 2016 Obsidian-Studios, Inc.
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

struct report {
    char *domain;
    bool domain_allocated;
    unsigned short emails;
    unsigned short omitted;
    unsigned short total;
    struct sub_report *sub_ptr;
    unsigned short sub_count;
};

struct sub_report {
    char *address;
    bool address_allocated;
    unsigned short emails;
    unsigned short omitted;
    unsigned short total;
    char *data;
    unsigned int data_length;
};

char * getConfigDir();

void freeReport(struct report *report);

void freeAddress(struct sub_report *sub_ptr);

void cleanup();

void exitError(char *msg);

void exitClean();

void exitNotImp(char *opt);

void initRptPtr();

void initSubPtr(struct sub_report *sub_ptr);

char ** addDir(char *dir);

short omitEmail(char *subject);

short inDateRange(struct tm *file_tm_ptr);

short createReport(char *directory);

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

struct args {
    short c;
    short days;
    short years;
};
