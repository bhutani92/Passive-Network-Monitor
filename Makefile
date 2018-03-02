OBJS = main.o
CC = g++
DEBUG = -g
CFLAGS = -Wall -Werror -Wno-deprecated-declarations -I. -lpcap -c $(DEBUG)
LFLAGS = -lpcap

mydump : $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) -o mydump $(LFLAGS)

main.o : main.h main.cpp
	$(CC) $(CFLAGS) main.cpp

clean :
	\rm -f *.o mydump *.tar

tar:
	tar zcvf mydump.tar.gz main.cpp main.h Makefile mydump README.txt
