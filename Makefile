CFLAGS += -Wall

all: tracertt tracepktiv

tracertt: tracertt.o
	$(CC) $(LDFLAGS) tracertt.o -o tracertt -lm -ltrace -ltcptools

tracepktiv: tracepktiv.o
	$(CC) $(LDFLAGS) tracepktiv.o -o tracepktiv -lm -ltrace

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm *.o tracertt tracepktiv

