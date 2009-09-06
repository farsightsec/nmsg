OBJS = \
	msg/domain_to_str.o \
	msg/dns_clear.o \
	msg/name_len_uncomp.o \
	msg/name_skip.o \
	msg/name_to_str.o \
	msg/name_unpack.o \
	msg/parse_header.o \
	msg/parse_message.o \
	msg/parse_message_rr.o \
	msg/parse_question_record.o \
	msg/parse_rdata.o \
	msg/print_data.o \
	msg/print_message.o \
	msg/print_question_record.o \
	msg/print_rr.o \
	msg/rdata_to_str.o \
	msg/valid_opcode.o \
	msg/valid_rcode.o

CC = gcc
CFLAGS = --std=gnu99 -O2 -ggdb -Wall -Wextra -Werror -I./include
DEBUG = -include debug.h
NDEBUG = -include nodebug.h

%.o : %.c
	$(CC) -c $(CFLAGS) $(NDEBUG) $< -o $@

dnsdump: $(OBJS) dnsdump.o
	$(CC) -o dnsdump $(OBJS) dnsdump.o -lpcap -lldns

all: $(OBJS)

clean:
	rm -f $(OBJS) dnsdump dnsdump.o

.PHONY: all clean
