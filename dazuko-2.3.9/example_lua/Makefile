# ----- Makefile ------------------------------------------------
# Makefile for the lua language binding of Dazuko

# common flags
CFLAGS += -Wall
CFLAGS += -fPIC
# CFLAGS += -DDEBUG

# Lua related flags, probably need to be tweaked
CFLAGS += -I$(HOME)/include
LUA_LDFLAGS = -L$(HOME)/lib -llua

# Dazuko related flags
CFLAGS += -I..
DAZUKO_LDFLAGS = -L../library -ldazuko

# Lua is not a standalone scripting language and does not have
# the "extension management" and "makefile maker" tools other
# languages like Python, Ruby, or Perl have -- so we have to
# setup our own build environment :(  yes this is just a start
UNAME = $(shell uname | tr '/-' '__')
ifeq ($(UNAME),Darwin)
  DYN = -dynamic -bundle
else
  DYN = -shared
endif
ifeq ($(UNAME),Linux)
  LDFLAGS += -ldl -lm
endif

# usually UNIX shared objects are named "lib<some>.so", but the
# default Lua cpath setting made me use this unusual name ...
LIBNAME = dazuko.so

TARGETS = $(LIBNAME) # example

all: $(TARGETS)

$(LIBNAME): libdazuko.o
	$(CC) $(CFLAGS) $(DYN) -o $@ $< $(LUA_LDFLAGS) $(DAZUKO_LDFLAGS) $(LDFLAGS)

example: example.o
	$(CC) $(CFLAGS) -o $@ $< $(LUA_LDFLAGS) $(DAZUKO_LDFLAGS) $(LDFLAGS)

clean:
	$(RM) *.o *.a
	$(RM) $(LIBNAME) example

# ----- E O F ---------------------------------------------------
