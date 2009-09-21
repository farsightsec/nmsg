AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/wdns

bin_PROGRAMS = wdns-dump-hex

if LIBPCAP
bin_PROGRAMS += wdns-dump-pcap
endif

wdns_dump_pcap_LDADD = ../wdns/libwdns.la -lpcap
wdns_dump_pcap_SOURCES = wdns-dump-pcap.c private.h

wdns_dump_hex_LDADD = ../wdns/libwdns.la
wdns_dump_hex_SOURCES = wdns-dump-hex.c private.h
