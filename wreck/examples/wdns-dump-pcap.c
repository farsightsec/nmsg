/* wdns-dump-pcap: read a pcap file, and optionally dump broken DNS messages */

/* XXX -- assumes all packets are DNS, use a bpf if not */
/* XXX -- doesn't handle fragments */
/* XXX -- only handles ethernet/ipv4 messages */

#include "private.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pcap.h>
#include <wdns.h>

static uint64_t count;
static uint64_t count_dump;

#define eth_type_ip	0x0800
#define eth_type_ipv6	0x86dd

#define advance(p, len, sz) do { (p) += (sz); (len) -= (sz); } while (0)
#define getu16(dst, src) do { memcpy(&(dst), src, 2); dst = ntohs(dst); } while (0)

void
packet_dump(u_char *dumper,
	    const struct pcap_pkthdr *hdr,
	    const u_char *pkt)
{
	pcap_dump(dumper, hdr, pkt);
	VERBOSE("count=%" PRIu64 " dumping broken packet\n", count);
	count_dump += 1;
}

void
packet_handler(u_char *dumper,
	       const struct pcap_pkthdr *hdr,
	       const u_char *pkt)
{
	const u_char *dns_p, *p;
	uint16_t e_type;
	uint16_t ip_len;
	uint32_t dns_len;
	uint32_t len = hdr->caplen;
	uint8_t ihl;
	wdns_message_t m;
	wdns_msg_status status;

	p = pkt;
	count++;

	VERBOSE("count=%" PRIu64 " parsing packet\n", count);

	/* ethernet */
	if (len < 14) {
		VERBOSE("count=%" PRIu64 " too short for ethernet\n", count);
		return;
	}
	advance(p, len, 12);
	getu16(e_type, p);
	advance(p, len, 2);
	if (e_type != eth_type_ip) {
		VERBOSE("count=%" PRIu64 " not IP e_type=%#.x\n", count, e_type);
		return;
	}

	/* skip ip */
	ihl = *p & 0x0f;
	if (len < ihl * 4U) {
		VERBOSE("count=%" PRIu64" IP too short\n", count);
		return;
	}
	getu16(ip_len, p + 2);
	if (ip_len < len)
		len = ip_len;
	advance(p, len, ihl * 4U);

	/* skip udp */
	if (len < 8) {
		VERBOSE("count=%" PRIu64" UDP too short\n", count);
		return;
	}
	advance(p, len, 8);

	/* dns header */
	if (len < 12) {
		VERBOSE("count=%" PRIu64" DNS header too short\n", count);
		return;
	}

	dns_p = p;
	dns_len = len;

	status = wdns_parse_message(&m, dns_p, dns_len);
	if (status == wdns_msg_success) {
		wdns_print_message(stdout, &m);
		wdns_clear_message(&m);
	} else {
		VERBOSE("wdns_msg_status=%u\n", status);
		packet_dump(dumper, hdr, pkt);
	}

	VERBOSE("\n");
	return;
}

int
main(int argc, char **argv) {
	pcap_t *pcap;
	pcap_dumper_t *dumper = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bpfp;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <INFILE> <OUTFILE> <BPF>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	pcap = pcap_open_offline(argv[1], errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_offline() failed: %s\n", errbuf);
		return (EXIT_FAILURE);
	}

	dumper = pcap_dump_open(pcap, argv[2]);
	if (dumper == NULL) {
		pcap_perror(pcap, "pcap_dump_open:");
		return (EXIT_FAILURE);
	}

	if (pcap_compile(pcap, &bpfp, argv[3], 1, 0) != 0) {
		pcap_perror(pcap, "pcap_compile:");
		pcap_close(pcap);
		pcap_dump_close(dumper);
		return (EXIT_FAILURE);
	} else {
		if (pcap_setfilter(pcap, &bpfp) != 0) {
			pcap_perror(pcap, "pcap_setfilter:");
			pcap_close(pcap);
			pcap_dump_close(dumper);
			return (EXIT_FAILURE);
		}
		pcap_freecode(&bpfp);
	}

	pcap_loop(pcap, -1, packet_handler, (u_char *) dumper);
	pcap_close(pcap);
	pcap_dump_close(dumper);

	fprintf(stderr, "count=%" PRIu64 "\n", count);
	fprintf(stderr, "count_dump=%" PRIu64 "\n", count_dump);

	return (EXIT_SUCCESS);
}
