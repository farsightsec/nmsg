AM_CFLAGS = @EXTRA_CFLAGS@

INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

EXTRA_DIST = email_client_postfix.py

noinst_PROGRAMS = \
	email_client \
	http_client \
	ipconn_client \
	linkpair_client \
	logline_client

email_client_LDADD = ../nmsg/libnmsg.la
email_client_SOURCES = email_client.c

http_client_LDADD = ../nmsg/libnmsg.la
http_client_SOURCES = http_client.c

ipconn_client_LDADD = ../nmsg/libnmsg.la
ipconn_client_SOURCES = ipconn_client.c

linkpair_client_LDADD = ../nmsg/libnmsg.la
linkpair_client_SOURCES = linkpair_client.c

logline_client_LDADD = ../nmsg/libnmsg.la
logline_client_SOURCES = logline_client.c
