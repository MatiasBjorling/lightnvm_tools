CC=gcc
CFLAGS=-c -Wall -g
LDFLAGS=
SOURCES=simple.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=simple
KDIR ?= /lib/modules/`uname -r`/build

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) -I$(KDIR) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o simple
