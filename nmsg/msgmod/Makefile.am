SUBDIRS = .

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@/nmsg

noinst_LTLIBRARIES = libnmsg_msgmod.la

libnmsg_msgmod_la_CFLAGS = $(AM_CFLAGS)
libnmsg_msgmod_la_SOURCES = \
	msgmod.c \
	transparent.c
