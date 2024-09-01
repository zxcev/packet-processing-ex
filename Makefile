.PHONY: all clean

SRCS = $(wildcard *.c)
PROGS = $(patsubst %.c,dist/%,$(SRCS))
CFLAGS = -Wall -Werror
LDFLAGS :=
LIBS := -lpcap

all: $(PROGS)

dist:
	mkdir -p dist

dist/%: %.c | dist
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

# %: %.c
# 	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean:
	rm -f $(PROGS)
