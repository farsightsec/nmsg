AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/wdns

bin_PROGRAMS = \
	wdns-deserialize-rrset \
	wdns-serialize-rrset \
	wdns-test-print-message

if LIBPCAP
bin_PROGRAMS += wdns-dump-pcap
endif

EXTRA_DIST = private.h hex.h

wdns_dump_pcap_LDADD = ../wdns/libwdns.la -lpcap
wdns_dump_pcap_SOURCES = wdns-dump-pcap.c

wdns_deserialize_rrset_LDADD = ../wdns/libwdns.la
wdns_deserialize_rrset_SOURCES = wdns-deserialize-rrset.c hex.c

wdns_serialize_rrset_LDADD = ../wdns/libwdns.la
wdns_serialize_rrset_SOURCES = wdns-serialize-rrset.c hex.c

wdns_test_print_message_LDADD = ../wdns/libwdns.la
wdns_test_print_message_SOURCES = wdns-hex-driver.c wdns-test-print-message.c
