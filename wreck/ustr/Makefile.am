AM_CFLAGS = @EXTRA_CFLAGS@

noinst_LTLIBRARIES = libustr.la

libustr_la_CFLAGS = $(AM_CFLAGS) -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -DNDEBUG
libustr_la_SOURCES = \
	ustr-b-opt-code.c \
	ustr-cmp-opt-code.c \
	ustr-fmt-opt-code.c \
	ustr-ins-opt-code.c \
	ustr-io-opt-code.c \
	ustr-main-opt-code.c \
	ustr-parse-opt-code.c \
	ustr-pool-opt-code.c \
	ustr-replace-opt-code.c \
	ustr-sc-opt-code.c \
	ustr-set-opt-code.c \
	ustr-split-opt-code.c \
	ustr-spn-opt-code.c \
	ustr-srch-opt-code.c \
	ustr-sub-opt-code.c \
	ustr-utf8-opt-code.c
