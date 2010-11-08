SUBDIRS = .

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@/nmsg

noinst_LTLIBRARIES = libnmsg_msgmod.la

libnmsg_msgmod_la_CFLAGS = \
	$(AM_CFLAGS) \
	@libprotobuf_c_cflags@ \
	@libustr_cflags@
libnmsg_msgmod_la_SOURCES = \
	lookup.c \
	message.c \
	msgmod.c \
	transparent.c \
	transparent.h \
	transparent_message.c \
	transparent_module.c \
	transparent_payload.c \
	transparent_pres.c
