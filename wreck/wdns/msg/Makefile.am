SUBDIRS = .

AM_CFLAGS = @EXTRA_CFLAGS@

EXTRA_DIST = gen_rrclass_to_str gen_rrtype_to_str

wdnsincludedir = $(includedir)/wdns

noinst_LTLIBRARIES = libwdns_msg.la

rrclass_to_str.c: ../constants.h
	./gen_rrclass_to_str

rrtype_to_str.c: ../constants.h
	./gen_rrtype_to_str

libwdns_msg_la_CFLAGS = $(AM_CFLAGS) -fgnu89-inline
libwdns_msg_la_SOURCES = \
	../constants.h \
	../buf.h \
	../msg.h \
	../../wdns.h \
	clear.c \
	compare_rr_rrset.c \
	copy_uname.c \
	count_labels.c \
	deserialize_rrset.c \
	domain_to_str.c \
	downcase_name.c \
	downcase_rdata.c \
	downcase_rrset.c \
	file_load_names.c \
	insert_rr_rrset_array.c \
	is_subdomain.c \
	left_chop.c \
	len_uname.c \
	message_to_str.c \
	parse_edns.c \
	parse_header.c \
	parse_message.c \
	parse_message_rr.c \
	parse_rdata.c \
	print_message.c \
	print_rr.c \
	print_rrset.c \
	print_rrset_array.c \
	private.h \
	opcode_to_str.c \
	rcode_to_str.c \
	rdata_to_str.c \
	record_descr.c \
	record_descr.h \
	rr_to_str.c \
	rr_to_ustr.c \
	rrclass_to_str.c \
	rrtype_to_str.c \
	rrset_array_to_str.c \
	rrset_array_to_ustr.c \
	rrset_to_str.c \
	rrset_to_ustr.c \
	serialize_rrset.c \
	sort_rrset.c \
	skip_name.c \
	str_to_name.c \
	unpack_name.c
