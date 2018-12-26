# CC = musl-gcc
CFLAGS  := -Wall -Wextra -Os
LDFLAGS := -flto

TARGET := uftpd

%.c: %.re.c
	re2c -W -T -o $@ $^

$(TARGET): uftpd.o cmdparser.o main.o

clean:
	rm -f *.o uftpd

.SECONDARY: $(TARGET).c
.PHONY: clean
