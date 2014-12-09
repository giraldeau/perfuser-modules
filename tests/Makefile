RM = rm -rf

CFLAGS = -O2 -Wall

TARGET = test_ioctl
OBJS = $(TARGET).o

.PHONY: all view clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^

$(TARGET).o: $(TARGET).c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(TARGET) $(OBJS)
