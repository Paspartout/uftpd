# CC = musl-gcc
CFLAGS  := -Wall -Wextra -Os
LDFLAGS := -flto

TARGET := uftpd

%.c: %.re.c
	re2c -T -o $@ $^

$(TARGET): uftpd.o cmdparser.o main.o

clean:
	rm -f *.o cmdparser

.SECONDARY: $(TARGET).c
.PHONY: clean
