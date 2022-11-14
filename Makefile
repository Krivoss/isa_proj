CC = g++
CFLAGS = -Wall -g
RM=rm -f
BIN=flow
TAR=xkriva30.tar
LFLAGS= -lpcap
.PHONY: all build pack clean

all: flow

run: flow
	./flow

flow: flow.o
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

%.o: %.cpp *.h
	$(CC) $(CFLAGS) -c $< -o $@ $(LFLAGS)

pack: clean
	tar -cf $(TAR) *.cpp *.h Makefile flow.1 manual.pdf

clean:
	rm -rf $(BIN) $(TAR) *.o