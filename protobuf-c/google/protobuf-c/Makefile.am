AM_CFLAGS = @EXTRA_CFLAGS@

protobufincludedir = $(includedir)/google/protobuf-c

lib_LTLIBRARIES =
nobase_protobufinclude_HEADERS =

lib_LTLIBRARIES += libnmsg_protobuf-c.la

nobase_protobufinclude_HEADERS += \
	protobuf-c.h \
	protobuf-c-private.h

libnmsg_protobuf_c_la_SOURCES = protobuf-c.c
libnmsg_protobuf_c_la_LDFLAGS = \
	-export-symbols-regex "^nmsg_protobuf_.*"
