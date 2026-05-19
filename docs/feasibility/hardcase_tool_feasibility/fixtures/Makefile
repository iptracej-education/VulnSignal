CC ?= clang
CFLAGS ?= -g -O0 -Wall -Wextra

all: hardcases.o

hardcases.o: hardcases.c
	$(CC) $(CFLAGS) -c hardcases.c -o hardcases.o

clean:
	rm -f hardcases.o hardcases.bc hardcases.ll compile_commands.json
