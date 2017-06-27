# Anti-Spam Server Proxy Report 
[![License](http://img.shields.io/badge/license-GPLv3-9977bb.svg?style=plastic)](https://github.com/Obsidian-StudiosInc/asspr/blob/master/LICENSE)
[![Build Status](https://img.shields.io/travis/Obsidian-StudiosInc/asspr/master.svg?colorA=9977bb&style=plastic)](https://travis-ci.org/Obsidian-StudiosInc/asspr)
[![Build Status](https://img.shields.io/shippable/5840e5c292fdea1000365227/master.svg?colorA=9977bb&style=plastic)](https://app.shippable.com/projects/5840e5c292fdea1000365227/)
[![Code Quality](https://img.shields.io/coverity/scan/12325.svg?colorA=9977bb&style=plastic)](https://scan.coverity.com/projects/obsidian-studiosinc-asspr)

Anti-Spam Server Proxy Report is a small program written in C that 
creates a report based on the emails in 
[ASSP's](http://assp.sourceforge.net/) directories. At the moment only 
notspam, spam and viruses folders. Reports contain the file name, To:, 
From:, and Subject: fields of each email in each folder. Providing a 
means to monitor the emails and [ASSP's](http://assp.sourceforge.net/) 
activity.

By default report start at the beginning of the day till the time the 
report is run. If run at 11:59PM/23:59, report will include that days 
emails. Ideally meant to be run once daily, but some modifications have 
been made to allow for other time frames. Please open issues for any 
bugs, feature requests, enhancements, etc.

## INSTALLATION

GNU Autotools are used to build and install asspr

```bash
./autogen.sh
make install
```

and your done.

The last step, make install simply copies asspr to /usr/sbin, and the 
man page to /usr/share/man/man8/. Which can be easily changed by 
modifying the make file. Or manually moving or placing the files.
