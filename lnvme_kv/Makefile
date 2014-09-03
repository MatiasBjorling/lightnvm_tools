CC=gcc
CFLAGS=-c -Wall -std=c99 -g
LDFLAGS=-lm
DFLAGS=-D_POSIX_SOURCE
SOURCES=vslkvtest.c vslkv.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=vslkv_test

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(DFLAGS) -I. $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)
