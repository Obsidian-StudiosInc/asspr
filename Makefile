CC = gcc
FLAGS = 
INCLUDE =
WITH = -w -Wall -Wno-trigraphs 

all : asspr

asspr : 
	$(CC) $(FLAGS) $(INCLUDE) $(WITH) asspr.c -o asspr

debug :
	$(CC) $(FLAGS) -g $(INCLUDE) $(WITH) asspr.c -o asspr

clean :
	rm asspr

test : 
	/usr/bin/valgrind --leak-check=yes --leak-check=full \
	--read-var-info=yes  --show-reachable=yes --track-origins=yes

install:
	mv asspr /usr/sbin/
	gzip -c asspr.8 > /usr/share/man/man8/asspr.8.gz
	chown root:root /usr/sbin/asspr
	chown root:root /usr/share/man/man8/asspr.8.gz
