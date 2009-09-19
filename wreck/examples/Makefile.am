INCLUDES = -I@top_srcdir@ -I@top_srcdir@/wdns

bin_PROGRAMS =

if LIBPCAP
bin_PROGRAMS += wdns-dump-pcap
endif

wdns_dump_pcap_LDADD = ../wdns/libwdns.la -lpcap
wdns_dump_pcap_SOURCES = wdns-dump-pcap.c
