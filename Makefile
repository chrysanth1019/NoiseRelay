# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -O2 -pthread \
  -DPACKAGE_NAME=\"noise-c\" \
  -DPACKAGE_TARNAME=\"noise-c\" \
  -DPACKAGE_VERSION=\"0.0.1\" \
  -DPACKAGE_STRING=\"noise-c 0.0.1\" \
  -DPACKAGE_BUGREPORT=\"\" \
  -DPACKAGE_URL=\"\" \
  -DPACKAGE=\"noise-c\" \
  -DVERSION=\"0.0.1\" \
  -DYYTEXT_POINTER=1 \
  -DHAVE_STDIO_H=1 \
  -DHAVE_STDLIB_H=1 \
  -DHAVE_STRING_H=1 \
  -DHAVE_INTTYPES_H=1 \
  -DHAVE_STDINT_H=1 \
  -DHAVE_STRINGS_H=1 \
  -DHAVE_SYS_STAT_H=1 \
  -DHAVE_SYS_TYPES_H=1 \
  -DHAVE_UNISTD_H=1 \
  -DSTDC_HEADERS=1 \
  -DSIZEOF_VOID_P=8 \
  -DHAVE_LIBRT=1 \
  -DHAVE_POLL=1 \
  -DHAVE_PTHREAD_PRIO_INHERIT=1 \
  -I. -I./noise-c/include

LDFLAGS = -pthread -lrt

# Files
SRCS = main.c echo-common.c
OBJS = $(SRCS:.c=.o)
LIBS = ./noise-c/src/protocol/libnoiseprotocol.a
TARGET = noise-relay

# Default target
all: $(TARGET)

# Link final binary
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)
