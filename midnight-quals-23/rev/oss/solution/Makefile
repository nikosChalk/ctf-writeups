

all: oss.angr.O0 oss.angr.O2

oss.angr.O0: oss.angr.c
	gcc -O0 -g -o oss.angr.O0 oss.angr.c -no-pie

oss.angr.O2: oss.angr.c
	gcc -O2 -g -o oss.angr.O2 oss.angr.c -no-pie

clean:
	rm -f oss.angr.O0 oss.angr.O2
