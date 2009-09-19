SUBDIRS = msg .

VERSION_INFO = 0:0:0

include_HEADERS = wreck.h

lib_LTLIBRARIES = libwreck.la

libwreck_la_SOURCES =
libwreck_la_LIBADD = msg/libwreck_msg.la
libwreck_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^wreck_.*"
