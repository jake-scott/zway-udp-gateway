BIN = udp-gw
SRCS = udp-gw.c
OBJS = $(SRCS:.c=.o)

CPPFLAGS = -D_GNU_SOURCE
CFLAGS = -std=c99
LDFLAGS =
LDLIBS = -lyajl

CC = gcc

ifdef DEBUG
    CPPFLAGS += -DDEBUG -g
endif

.DEFAULT: all
.PHONY: all

all: $(BIN)

$(BIN) : $(OBJS)

