CC = gcc
CFLAGS = -O3
LDFLAGS = -O3

all: chall

chall: chall.o aes.o aes-gcm.o
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o chall