AM_CFLAGS = @EXTRA_CFLAGS@

INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

EXTRA_DIST = email_client_postfix.py

noinst_PROGRAMS = \
	email_client \
	http_client \
	ipconn_client \
	logline_client \
	nmsg_callback \
	print_srcip \
	nmsg-dnsqr2pcap

email_client_LDADD = ../nmsg/libnmsg.la
email_client_SOURCES = email_client.c

http_client_LDADD = ../nmsg/libnmsg.la
http_client_SOURCES = http_client.c

ipconn_client_LDADD = ../nmsg/libnmsg.la
ipconn_client_SOURCES = ipconn_client.c

logline_client_LDADD = ../nmsg/libnmsg.la @libustr_libadd@
logline_client_SOURCES = logline_client.c
logline_client_CFLAGS = $(AM_CFLAGS) @libustr_cflags@
logline_client_LDFLAGS = @libustr_ldflags@

nmsg_callback_LDADD = ../nmsg/libnmsg.la
nmsg_callback_SOURCES = nmsg_callback.c

print_srcip_LDADD = ../nmsg/libnmsg.la
print_srcip_SOURCES = print_srcip.c

nmsg_dnsqr2pcap_LDADD = ../nmsg/libnmsg.la @libprotobuf_c_libadd@
nmsg_dnsqr2pcap_SOURCES = nmsg-dnsqr2pcap.c
nmsg_dnsqr2pcap_CFLAGS = @libprotobuf_c_cflags@ @libpcap_cflags@
nmsg_dnsqr2pcap_LDFLAGS = @libprotobuf_c_ldflags@ @libpcap_ldflags@
