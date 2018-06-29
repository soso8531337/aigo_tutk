TARGET=i4Remote
export PATH=/home/dongxiangqian/baidu/pcs/opt/buildroot-gcc342/bin:/usr/kerberos/bin:/usr/local/bin:/bin:/usr/bin:/opt/buildroot-gcc342/bin:/home/dongxiangqian/bin
CC=mipsel-linux-gcc
CFLAGS=-L../lib -I../include 
ALL: clean $(TARGET)
SRC=$(wildcard *.c)
OBJS=$(SRC:.c=.o)
 
i4Remote:$(OBJS) 
	$(CC) -Wall -O2 -o  $(TARGET)  $^  $(CFLAGS) -lP2PTunnelAPIs -lRDTAPIs -lIOTCAPIs -lpthread -lrt 
%.o:%.c
	$(CC) -c -Wall -O2 -o $@ $^ $(CFLAGS) $(LDFLAGS)
 
clean:
	rm -rf *.o *~ i4Remote 
