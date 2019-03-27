include Makefile.libs

CFLAGS = -Wall
CC = gcc -g

SRC=$(wildcard *.c)

crack: $(SRC) test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

check: crack
	@./crack -single   users4 4 | tee check.out
	@./crack -speedy   users4 4 | tee -a check.out
	@./crack -multiple users4 4 | tee -a check.out
	@./crack -stealthy users4 4 | tee -a check.out

single: crack
	@./crack -single users4 4
	
multiple: crack
	@./crack -multiple users4 4
	
speedy: crack
	@./crack -speedy users4 4
	
stealthy: crack
	@./crack -stealthy users4 4
	
grade: 
	@if [ -s "check.out" ] ; \
	then \
		./grade.sh ; \
	else \
		make check grade; \
	fi;

clean:
	rm -f passwd crack check.out *.gz

submit:
	tar czvf ~/CMPS122-Lab1.tar.gz --exclude=crack.h --exclude=users* *.c *.h Makefile.libs
