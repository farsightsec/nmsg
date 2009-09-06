#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>
#include <ldns/ldns.h>

#include <wreck.h>

static uint32_t count;
static uint32_t count_dump;
static uint32_t count_compare;

void
packet_handler(u_char *dumper, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	bool status_ldns;
	bool status_wreck;
	wreck_status status;
	wreck_dns_query_t q;

	uint32_t len = hdr->caplen;
	uint16_t qdcount, ancount, nscount, arcount;

	const u_char *dns_p, *p;
	uint32_t dns_len;

	p = pkt;

	count++;

	/* skip ethernet */
	if (len < 16U) {
		VERBOSE("skip ethernet\n");
		return;
	}
	p += 14;
	len -= 14;

	/* skip ip */
	uint8_t ihl = *p & 0x0f;
	if (len < ihl*4U) {
		VERBOSE("skip ip\n");
		return;
	}
	uint16_t ip_len = ntohs(*((uint16_t *) (p+2)));
	if (ip_len < len)
		len = ip_len;
	p += ihl*4;
	len -= ihl *4;

	/* skip udp */
	if (len < 8) {
		VERBOSE("skip udp\n");
		return;
	}
	p += 8;
	len -= 8;

	/* dns header */
	if (len < 12) {
		VERBOSE("dns header\n");
		return;
	}

	dns_p = p;
	dns_len = len;

	VERBOSE("parsing packet #%u\n", count);

	ldns_pkt *lpkt;
	ldns_status lstatus = ldns_wire2pkt(&lpkt, p, len);
	if (lstatus == LDNS_STATUS_OK) {
		ldns_pkt_free(lpkt);
		status_ldns = true;
	} else {
		status_ldns = false;
	}

	status = wreck_parse_header(p, len, &q.id, &q.flags, &qdcount, &ancount, &nscount, &arcount);
	if (status != wreck_success) {
		status_wreck = false;
		goto compare;
	}

	p += 12;
	len -= 12;

	/*
	if ((WRECK_DNS_FLAGS_QR(q.flags) == 0) && (qdcount >= 1)) {
		if ((WRECK_DNS_FLAGS_OPCODE(q.flags) == 0) &&
		    (WRECK_DNS_FLAGS_RCODE(q.flags) == 0))
		{
			status = wreck_parse_question_record(p, p + len, &q.question);
			if (status == wreck_success) {
				status_wreck = true;
				free(q.question.rrname.data);
			} else {
				status_wreck = false;
				goto compare;
			}
		} else {
			goto skip;
		}
	} else {
	*/
		if (WRECK_DNS_FLAGS_OPCODE(q.flags) == 0) {
			wreck_dns_response_t r;
			status = wreck_parse_message(dns_p, dns_p + dns_len, &r);
			if (status == wreck_success) {
				status_wreck = true;
				free(r.question.rrname.data);
				goto compare;
			} else {
				status_wreck = false;
				goto compare;
			}
		} else {
			goto skip;
		}
	//}

compare:
	count_compare++;
	if (qdcount == 1 && status_wreck == true && status_ldns == false) {
		pcap_dump(dumper, hdr, pkt);
		count_dump++;
		printf("count=%u count_dump=%u status_wreck=%u status_ldns=%u\n", count, count_dump, status_wreck, status_ldns);
		if (status_wreck == false)
			printf("wreck fail: %d\n", status);
		if (status_ldns == false)
			printf("ldns fail: %s\n", ldns_get_errorstr_by_id(lstatus));
	}
skip:
#if DEBUG
	printf("\n");
#endif
	return;
}

int
main(int argc, char **argv) {
	pcap_t *pcap;
	pcap_dumper_t *dumper;
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

	fprintf(stderr, "count=%u\n", count);
	fprintf(stderr, "count_compare=%u\n", count_compare);
	fprintf(stderr, "count_dump=%u\n", count_dump);

	if (count_dump == 0)
		unlink(argv[2]);

	return (EXIT_SUCCESS);
}
