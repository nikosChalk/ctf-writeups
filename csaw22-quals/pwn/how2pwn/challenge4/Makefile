

all: myebpf myebpf-thin

myebpf: myebpf.c
	gcc -g -O0 myebpf.c -o myebpf

myebpf-thin: myebpf-thin.c
	gcc -g -O0 myebpf-thin.c -o myebpf-thin

clean:
	rm -rf myebpf myebpf-thin *.o
