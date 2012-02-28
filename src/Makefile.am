AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

bin_PROGRAMS = nmsgtool
nmsgtool_CFLAGS = \
	$(AM_CFLAGS) \
	@libpcap_cflags@ \
	@libprotobuf_c_cflags@ \
	@libzmq_cflags@
nmsgtool_LDADD = ../nmsg/libnmsg.la
nmsgtool_LDFLAGS = \
	@libpcap_ldflags@ \
	@libzmq_ldflags@
nmsgtool_SOURCES = \
	argv.c \
	argv.h \
	argv_loc.h \
	daemon.c \
	getsock.c \
	io.c \
	kickfile.c \
	kickfile.h \
	nmsgtool.c \
	nmsgtool.h \
	process_args.c \
	rwfile.c \
	unescape.c

noinst_PROGRAMS = crc32c_test
crc32c_CFLAGS = $(AM_CFLAGS)
crc32c_test_SOURCES = crc32c_test.c
crc32c_test_LDADD = ../nmsg/libnmsg.la

EXTRA_DIST = args.c
