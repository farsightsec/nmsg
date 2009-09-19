SUBDIRS = .

AM_CFLAGS = -I@top_srcdir@/wdns

wdnsincludedir = $(includedir)/wdns

nobase_wdnsinclude_HEADERS = \
	constants.h \
	msg.h

noinst_LTLIBRARIES = libwdns_msg.la

libwdns_msg_la_CFLAGS =
libwdns_msg_la_SOURCES = \
	clear.c \
	domain_to_str.c \
	name_downcase.c \
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
	print_rrset.c \
	print_rrset_array.c \
	rdata_to_str.c \
	valid_opcode.c \
	valid_rcode.c
