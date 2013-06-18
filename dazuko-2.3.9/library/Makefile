CC ?= cc
RM ?= rm -f
CFLAGS = -Wall -O
CFLAGS += -I..
CFLAGS += -fPIC
OBJS = dazukoio_core.o dazukoio_trusted_core.o dazuko_transport.o dazukoio_unix.o
OBJS += dazukoio_linux_compat1.o

all: libdazuko.a

libdazuko.a: $(OBJS)
	ar r libdazuko.a $(OBJS)
	ranlib libdazuko.a

dazukoio_core.o: ../dazukoio_core.c ../dazukoio_core.h
	$(CC) $(CFLAGS) -c ../dazukoio_core.c -o dazukoio_core.o

dazukoio_trusted_core.o: ../dazukoio_trusted_core.c
	$(CC) $(CFLAGS) -c ../dazukoio_trusted_core.c -o dazukoio_trusted_core.o

dazuko_transport.o: ../dazuko_transport.c ../dazuko_transport.h
	$(CC) $(CFLAGS) -c ../dazuko_transport.c -o dazuko_transport.o

dazukoio_unix.o: ../dazukoio_unix.c ../dazukoio_unix.h
	$(CC) $(CFLAGS) -c ../dazukoio_unix.c -o dazukoio_unix.o

dazukoio_linux_compat1.o: ../dazukoio_linux_compat1.c ../dazukoio_linux_compat1.h
	$(CC) $(CFLAGS) -c ../dazukoio_linux_compat1.c -o dazukoio_linux_compat1.o

clean:
	$(RM) -f *.o *.a
