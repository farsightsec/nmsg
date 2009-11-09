AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/wdns

bin_PROGRAMS = \
	wdns-test-print-message \
	wdns-test-deserialize-rrset \
	wdns-test-serialize-rrset

if LIBPCAP
bin_PROGRAMS += wdns-dump-pcap
endif

EXTRA_DIST = private.h hex.h

wdns_dump_pcap_LDADD = ../wdns/libwdns.la -lpcap
wdns_dump_pcap_SOURCES = wdns-dump-pcap.c

wdns_test_print_message_LDADD = ../wdns/libwdns.la
wdns_test_print_message_SOURCES = wdns-hex-driver.c wdns-test-print-message.c

wdns_test_deserialize_rrset_LDADD = ../wdns/libwdns.la
wdns_test_deserialize_rrset_SOURCES = wdns-hex-driver.c wdns-test-deserialize-rrset.c

wdns_test_serialize_rrset_LDADD = ../wdns/libwdns.la
wdns_test_serialize_rrset_SOURCES = wdns-hex-driver.c wdns-test-serialize-rrset.c
