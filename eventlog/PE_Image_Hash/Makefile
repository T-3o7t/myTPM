CC      = gcc
CFLAGS  = -Wall -O2 
LDFLAGS = -lcrypto -lssl

TARGET  = pe_image_hash_evp

SRCS    = pe_image_hash_evp.c 
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)
