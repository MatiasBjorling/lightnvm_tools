CC=gcc
CFLAGS=-c -Wall -g
LDFLAGS=
SOURCES=ioctl_test.c cutest/CuTest.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=ioctl_test

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) -Icutest $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)
