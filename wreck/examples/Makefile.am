AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/wdns

bin_PROGRAMS = wdns-dump-hex wdns-deserialize-rrset wdns-serialize-rrset

if LIBPCAP
bin_PROGRAMS += wdns-dump-pcap
endif

wdns_dump_pcap_LDADD = ../wdns/libwdns.la -lpcap
wdns_dump_pcap_SOURCES = wdns-dump-pcap.c private.h

wdns_dump_hex_LDADD = ../wdns/libwdns.la
wdns_dump_hex_SOURCES = wdns-dump-hex.c private.h hex.c

wdns_deserialize_rrset_LDADD = ../wdns/libwdns.la
wdns_deserialize_rrset_SOURCES = wdns-deserialize-rrset.c private.h hex.c

wdns_serialize_rrset_LDADD = ../wdns/libwdns.la
wdns_serialize_rrset_SOURCES = wdns-serialize-rrset.c private.h hex.c
