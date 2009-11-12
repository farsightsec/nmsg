AM_CFLAGS = @EXTRA_CFLAGS@

protobufincludedir = $(pkgincludedir)/google/protobuf-c

lib_LTLIBRARIES =
nobase_protobufinclude_HEADERS =

if INTERNAL_PROTOBUF_C
lib_LTLIBRARIES += libnmsg_protobuf-c.la

nobase_protobufinclude_HEADERS += \
	protobuf-c.h \
	protobuf-c-private.h
endif


libnmsg_protobuf_c_la_SOURCES = protobuf-c.c
libnmsg_protobuf_c_la_LDFLAGS = \
	-export-symbols-regex "^nmsg_protobuf_.*"
