CFLAGS  := -Wall -Wextra -g -Og
LDFLAGS := -flto

TARGET := uftpd

%.c: %.re.c
	re2c -T -o $@ $^

$(TARGET): uftpd.o cmdparser.o

clean:
	rm -f *.o cmdparser

.SECONDARY: $(TARGET).c
.PHONY: clean
