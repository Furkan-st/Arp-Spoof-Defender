CC = gcc
CFLAGS = -Wall -Wextra -pthread
LDFLAGS = -pthread

# Platformu ayarla:
ifeq ($(OS),Windows_NT)
    CFLAGS += -DOS_WINDOWS
    LDFLAGS += -lws2_32 -liphlpapi
    RM = del /Q
    EXE = .exe
else
    CFLAGS += -DOS_LINUX
    RM = rm -f
    EXE =
endif

SRC = main.c ip_util.c act_utils.c arp_parse.c
OBJ = $(SRC:.c=.o)
TARGET = arp_protect$(EXE)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJ) $(TARGET)
