SUBDIRS = .

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@/wdns

wdnsincludedir = $(includedir)/wdns

nobase_wdnsinclude_HEADERS = \
	constants.h \
	msg.h

noinst_LTLIBRARIES = libwdns_msg.la

rrclass_to_str.c: constants.h gen_rrclass_to_str
	./gen_rrclass_to_str

rrtype_to_str.c: constants.h gen_rrtype_to_str
	./gen_rrtype_to_str

libwdns_msg_la_CFLAGS = $(AM_CFLAGS)
libwdns_msg_la_SOURCES = \
	clear.c \
	compare_rr_rrset.c \
	domain_to_str.c \
	downcase_name.c \
	downcase_rdata.c \
	downcase_rrset.c \
	insert_rr_rrset_array.c \
	len_uname.c \
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
	rdata_to_str.c \
	record_descr.c \
	rrclass_to_str.c \
	rrtype_to_str.c \
	skip_name.c \
	uname_copy.c \
	valid_opcode.c \
	valid_rcode.c
