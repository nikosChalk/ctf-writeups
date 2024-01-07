
OPEN_TEE_PATH=/opt/OpenTee
CFLAGS += -g -Wall -I/home/ctf/opentee/libtee/include -I./
LDADD += -L$(OPEN_TEE_PATH)/lib/ -ltee

.PHONY: all
all: grade_ca load_grade_ca

grade_ca: grade_ca.c grade_ca.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

load_grade_ca: load_grade_ca.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -f *.o grade_ca load_grade_ca
