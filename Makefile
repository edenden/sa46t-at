#Makefile
#char code "LF(UNIX)" is required!!

OPTIONS = -O1
PROGS = main

all: $(PROGS)

main: main.o translate.o session.o icmp.o checksum.o mtu.o
	cc $(OPTIONS) -o sa46t-at main.o translate.o session.o icmp.o checksum.o mtu.o -l pthread
	rm *.o

main.o : main.c
	cc $(OPTIONS) -c main.c

translate.o : translate.c
	cc $(OPTIONS) -c translate.c

session.o : session.c
	cc $(OPTIONS) -c session.c

icmp.o : icmp.c
	cc $(OPTIONS) -c icmp.c

checksum.o : checksum.c
	cc $(OPTIONS) -c checksum.c

mtu.o : mtu.c
	cc $(OPTIONS) -c mtu.c
