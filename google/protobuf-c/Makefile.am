AM_CFLAGS = @EXTRA_CFLAGS@

VERSION_INFO = 0:0:0

protobufincludedir = $(pkgincludedir)/google/protobuf-c

lib_LTLIBRARIES = libnmsg_protobuf-c.la

nobase_protobufinclude_HEADERS = \
	protobuf-c.h \
	protobuf-c-private.h

libnmsg_protobuf_c_la_SOURCES = protobuf-c.c
libnmsg_protobuf_c_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^nmsg_protobuf_.*"
