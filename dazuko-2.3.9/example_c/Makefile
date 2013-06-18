CC ?= cc
RM ?= rm -f
CFLAGS = -Wall -O
CFLAGS += -I..
LFLAGS = -L../library

all: example example_mt

lib:
	cd ../library && make

example: example.c lib
	$(CC) $(CFLAGS) $(LFLAGS) -o example example.c -ldazuko

example_mt: example_mt.c lib
	$(CC) $(CFLAGS) $(LFLAGS) -pthread -o example_mt example_mt.c -ldazuko

clean:
	$(RM) example example_mt *.o
