CC = g++
CFLAGS = -Wall -g
RM=rm -f
BIN=flow
TAR=xkriva30.tar
SRC= $(wildcard *.cpp)
LFLAGS= -lpcap
.PHONY: all build pack clean
PORT=12345

all: flow

run: flow
	./flow

flow: flow.o
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

%.o: %.cpp *.h
	$(CC) $(CFLAGS) -c $< -o $@ $(LFLAGS)


pack: clean
	tar -cf $(TAR) $(SRC) *.h Makefile flow.1 manual.pdf

clean:
	rm -rf $(BIN) $(TAR) *.o