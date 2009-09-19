SUBDIRS = .

AM_CFLAGS = -I@top_srcdir@/wdns

wdnsincludedir = $(includedir)/wdns

nobase_wdnsinclude_HEADERS = \
	constants.h \
	msg.h

noinst_LTLIBRARIES = libwdns_msg.la

class_to_str.c:
	./gen_class_to_str

libwdns_msg_la_CFLAGS =
libwdns_msg_la_SOURCES = \
	class_to_str.c \
	clear.c \
	compare_rr_rrset.c \
	domain_to_str.c \
	insert_rr_rrset_array.c \
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
	print_message.c \
	print_question_record.c \
	print_rr.c \
	print_rrset.c \
	print_rrset_array.c \
	rdata_to_str.c \
	valid_opcode.c \
	valid_rcode.c
