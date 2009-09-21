SUBDIRS = .

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@/wdns

wdnsincludedir = $(includedir)/wdns

nobase_wdnsinclude_HEADERS = \
	constants.h \
	msg.h

noinst_LTLIBRARIES = libwdns_msg.la

class_to_str.c: constants.h gen_class_to_str
	./gen_class_to_str

type_to_str.c: constants.h gen_type_to_str
	./gen_type_to_str

libwdns_msg_la_CFLAGS = $(AM_CFLAGS)
libwdns_msg_la_SOURCES = \
	class_to_str.c \
	clear.c \
	compare_rr_rrset.c \
	domain_to_str.c \
	downcase_rdata.c \
	insert_rr_rrset_array.c \
	name_downcase.c \
	name_len_uncomp.c \
	name_skip.c \
	name_to_str.c \
	name_unpack.c \
	parse_edns.c \
	parse_header.c \
	parse_message.c \
	parse_message_rr.c \
	parse_rdata.c \
	print_bytes.c \
	print_message.c \
	print_rr.c \
	print_rrset.c \
	print_rrset_array.c \
	record_descr.c \
	rdata_to_str.c \
	type_to_str.c \
	uname_copy.c \
	valid_opcode.c \
	valid_rcode.c
