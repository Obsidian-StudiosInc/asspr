CC = gcc
FLAGS = 
INCLUDE =
WITH = -w -Wall -Wno-trigraphs 

all : asspr

asspr : 
	$(CC) $(FLAGS) -g $(INCLUDE) $(WITH) asspr.c -o asspr

clean :
	rm asspr

install:
	mv asspr /usr/sbin/
	cp asspr.8.gz  /usr/share/man/man8/
	chown root /usr/sbin/asspr
	chgrp root /usr/sbin/asspr
	chown root /usr/share/man/man8/asspr.8.gz
	chgrp root /usr/share/man/man8/asspr.8.gz

