AM_CFLAGS = @EXTRA_CFLAGS@

INCLUDES = -I$(top_srcdir)/nmsg

EXTRA_DIST = email_client_postfix.py

noinst_PROGRAMS = \
	linkpair_client \
	http_client \
	email_client \
	ipconn_client

linkpair_client_LDADD = ../nmsg/libnmsg.la
linkpair_client_SOURCES = linkpair_client.c

http_client_LDADD = ../nmsg/libnmsg.la
http_client_SOURCES = http_client.c

email_client_LDADD = ../nmsg/libnmsg.la
email_client_SOURCES = email_client.c

ipconn_client_LDADD = ../nmsg/libnmsg.la
ipconn_client_SOURCES = ipconn_client.c
