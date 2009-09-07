SUBDIRS = .

AM_CFLAGS = -I@top_srcdir@/wreck

nobase_pkginclude_HEADERS = \
	dns_constants.h \
	msg.h

noinst_LTLIBRARIES = libwreck_msg.la

libwreck_msg_la_CFLAGS =
libwreck_msg_la_SOURCES = \
	dns_clear.c \
	domain_to_str.c \
	name_len_uncomp.c \
	name_skip.c \
	name_to_str.c \
	name_unpack.c \
	parse_header.c \
	parse_message.c \
	parse_message_rr.c \
	parse_question_record.c \
	parse_rdata.c \
	print_data.c \
	print_message.c \
	print_question_record.c \
	print_rr.c \
	rdata_to_str.c \
	valid_opcode.c \
	valid_rcode.c
