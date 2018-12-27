# CC = musl-gcc
CFLAGS  := -Wall -Wextra -O0 -g
LDFLAGS := -flto

TARGET := uftpd

%.c: %.re
	re2c -W -T -o $@ $^

$(TARGET): uftpd.o cmdparser.o main.o

clean:
	rm -f *.o uftpd

.SECONDARY: $(TARGET).c
.PHONY: clean
