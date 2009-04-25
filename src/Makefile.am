AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

bin_PROGRAMS = nmsgtool
nmsgtool_LDADD = ../nmsg/libnmsg.la
nmsgtool_LDFLAGS = -lpcap
nmsgtool_SOURCES = \
	argv.c \
	argv.h \
	argv_loc.h \
	chalias.c \
	chalias.h \
	getsock.c \
	io.c \
	kickfile.c \
	kickfile.h \
	nmsgtool.c \
	process_args.c \
	rwfile.c \
	unescape.c
