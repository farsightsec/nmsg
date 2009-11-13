SUBDIRS = msg .

AM_CFLAGS = @EXTRA_CFLAGS@

VERSION_INFO = 0:0:0

wdnsincludedir = $(includedir)/wdns

wdnsinclude_HEADERS = \
	buf.h \
	constants.h \
	msg.h

lib_LTLIBRARIES = libwdns.la

libwdns_la_SOURCES =
libwdns_la_LIBADD = msg/libwdns_msg.la
libwdns_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^wdns_.*"
