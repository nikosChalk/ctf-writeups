
CC=gcc
CFLAGS=-g -O0

.PHONY: all
all: dummy

dummy: dummy.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf *.o dummy
