INCLUDES = -I@top_srcdir@ -I@top_srcdir@/wreck

bin_PROGRAMS =

if LIBPCAP
bin_PROGRAMS += wreck-pcapdump
endif

wreck_pcapdump_LDADD = ../wreck/libwreck.la -lpcap
wreck_pcapdump_SOURCES = wreck-pcapdump.c
