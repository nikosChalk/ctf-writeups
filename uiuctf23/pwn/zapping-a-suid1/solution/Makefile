
CC=gcc
CFLAGS=-g -Os -fPIE

all: exploit.b64

# base64 encoded exploit for easy copy-paster transfer
exploit.b64: exploit
	cat $< | base64 -w 0 > $@

# Define custom Elf64_Ehdr->e_entry to be `mymain` function
exploit: shellcode.o exploit.o
	$(CC) $(CFLAGS) -Wl,-emymain -nostartfiles -o $@ $^

shellcode.o: shellcode-flag.S
	$(CC) $(CFLAGS) -c -o $@ $<
exploit.o: exploit.c
	$(CC) $(CFLAGS) -c -o $@ $<


clean:
	rm -rf *.o exploit exploit.b64
