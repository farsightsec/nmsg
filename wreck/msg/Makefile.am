SUBDIRS = .

VERSION_INFO = 0:0:0
INCLUDES = -I@top_srcdir@

lib_LTLIBRARIES = libwreck.la

libwreck_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^wreck_.*"
libwreck_la_SOURCES = \
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
