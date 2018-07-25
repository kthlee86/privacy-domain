CFLAGS += -O3 -g

CURR_DIR = $(shell pwd)
SOURCES=chacha.c
OBJS=$(SOURCES:.c=.o)

#SOURCES=chacha.s
#OBJS=$(SOURCES:.s=.o)

PROGRAM=test

all: $(PROGRAM)

test: $(OBJS) test.c
	gcc $(CFLAGS) $^ -o $@

chacha: chacha.c
	gcc $(CFLAGS) $^ -o $@

#chacha: chacha.s
	#gcc chacha.s -o $@

clean:
	-rm -f $(PROGRAM) $(OBJS)
