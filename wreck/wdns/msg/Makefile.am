SUBDIRS = .

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@/wdns

EXTRA_DIST = gen_rrclass_to_str gen_rrtype_to_str

wdnsincludedir = $(includedir)/wdns

nobase_wdnsinclude_HEADERS = \
	constants.h \
	msg.h

noinst_LTLIBRARIES = libwdns_msg.la

rrclass_to_str.c: constants.h
	./gen_rrclass_to_str

rrtype_to_str.c: constants.h
	./gen_rrtype_to_str

libwdns_msg_la_CFLAGS = $(AM_CFLAGS)
libwdns_msg_la_SOURCES = \
	buf.h \
	clear.c \
	compare_rr_rrset.c \
	constants.h \
	copy_uname.c \
	deserialize_rrset.c \
	domain_to_str.c \
	downcase_name.c \
	downcase_rdata.c \
	downcase_rrset.c \
	insert_rr_rrset_array.c \
	len_uname.c \
	msg.h \
	name_to_str.c \
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
	private.h \
	rdata_to_str.c \
	record_descr.c \
	record_descr.h \
	rrclass_to_str.c \
	rrtype_to_str.c \
	serialize_rrset.c \
	sort_rrset.c \
	skip_name.c \
	unpack_name.c
