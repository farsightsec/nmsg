/* packet nmsg message module */

/*
 * Copyright (c) 2013 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

#include "packet.pb-c.h"

/* Exported via module context. */

static nmsg_res
packet_pcap_init(void *clos, nmsg_pcap_t);

static nmsg_res
packet_pkt_to_payload(void *clos, nmsg_pcap_t, nmsg_message_t *);

/* Data. */

struct nmsg_msgmod_field packet_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "payload_type",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "payload",
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor = NMSG_VENDOR_BASE,
	.msgtype = { NMSG_VENDOR_BASE_PACKET_ID, NMSG_VENDOR_BASE_PACKET_NAME },
	.pbdescr = &nmsg__base__packet__descriptor,
	.fields = packet_fields,
	.pkt_to_payload = packet_pkt_to_payload,
	.pcap_init = packet_pcap_init
};

static nmsg_res
packet_pcap_init(void *clos, nmsg_pcap_t pcap)
{
	const char *dlt_name = NULL;
	int dlt;

	dlt = nmsg_pcap_get_datalink(pcap);
	dlt_name = pcap_datalink_val_to_name(dlt);
	if (dlt_name == NULL)
		dlt_name = "(unknown)";

	switch (dlt) {
	case DLT_EN10MB:
	case DLT_RAW:
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
#endif
		/* these types are fine, handle them */
		break;
	case DLT_NULL:
	case DLT_LOOP:
		/* these types require platform and runtime specific
		 * interpretation, so it is only safe to handle them on
		 * the original system which captured these frames */
		if (nmsg_pcap_get_type(pcap) == nmsg_pcap_type_live)
			return (nmsg_res_success);
		if (nmsg_get_debug() >= 1) {
			dlt_name = pcap_datalink_val_to_name(dlt);
			fprintf(stderr, "%s: ERROR: Refusing to process packets from "
				"a non-live pcap handle with datalink type %s\n",
				__func__, dlt_name);
		}
		return (nmsg_res_failure);
	default:
		if (nmsg_get_debug() >= 1) {
			fprintf(stderr, "%s: ERROR: Unable to open pcap handle with "
				"datalink type %s\n", __func__, dlt_name);
		}
		return (nmsg_res_failure);
	}

	if (nmsg_get_debug() >= 2)
		fprintf(stderr, "%s: opening pcap handle with datalink type %s\n",
			__func__, dlt_name);
	return (nmsg_res_success);
}

static nmsg_res
packet_load(nmsg_pcap_t pcap, Nmsg__Base__Packet *packet,
	    struct pcap_pkthdr *pkt_hdr,
	    const uint8_t *pkt)
{
#define advance_pkt(_pkt, _len, _sz) do { \
        (_pkt) += (_sz); \
        (_len) -= (_sz); \
} while (0)
	size_t len = pkt_hdr->caplen;
	uint32_t type = 0;

	/* only operate on complete packets */
	if (pkt_hdr->caplen != pkt_hdr->len)
		return (nmsg_res_again);

	packet->payload_type = NMSG__BASE__PACKET_TYPE__IP;

	switch (nmsg_pcap_get_datalink(pcap)) {
	case DLT_EN10MB:
		if (len < sizeof(struct nmsg_ethhdr))
			return (nmsg_res_again);
		advance_pkt(pkt, len, offsetof(struct nmsg_ethhdr, ether_type));
		load_net16(pkt, &type);
		advance_pkt(pkt, len, 2);
		if (type == ETHERTYPE_VLAN) {
			if (len < 4)
				return (nmsg_res_again);
			advance_pkt(pkt, len, 2);
			load_net16(pkt, &type);
			advance_pkt(pkt, len, 2);
		}
		if (type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
			goto success;
		return (nmsg_res_again);
		break;
	case DLT_RAW:
		goto success;
		break;
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		if (len < 16)
			return (nmsg_res_again);
		advance_pkt(pkt, len, 14);
		load_net16(pkt, &type);
		advance_pkt(pkt, len, 2);
		if (type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
			goto success;
		return (nmsg_res_again);
		break;
#endif
	case DLT_NULL:
		if (len < sizeof(type))
			return (nmsg_res_again);
		memcpy(&type, pkt, sizeof(type));
		advance_pkt(pkt, len, sizeof(type));
		if (type == PF_INET || type == PF_INET6)
			goto success;
		return (nmsg_res_again);
		break;
	case DLT_LOOP:
		if (len < sizeof(type))
			return (nmsg_res_again);
		load_net32(pkt, &type);
		advance_pkt(pkt, len, sizeof(type));
		if (type == PF_INET || type == PF_INET6)
			goto success;
		return (nmsg_res_again);
		break;
	default:
		return (nmsg_res_failure);
	}
	return (nmsg_res_failure);
success:
	packet->payload.data = (uint8_t *) pkt;
	packet->payload.len = len;
	return (nmsg_res_success);
#undef advance_pkt
}

static nmsg_res
packet_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m)
{
	Nmsg__Base__Packet packet;
	ProtobufCBufferSimple sbuf = {{0}};
	nmsg_res res;
	const uint8_t *pkt_data;
	struct pcap_pkthdr *pkt_hdr;
	struct timespec ts;
	size_t buf_sz;

	res = nmsg_pcap_input_read_raw(pcap, &pkt_hdr, &pkt_data, &ts);
	if (res != nmsg_res_success)
		return (res);

	nmsg__base__packet__init(&packet);

	res = packet_load(pcap, &packet, pkt_hdr, pkt_data);
	if (res != nmsg_res_success)
		return (res);

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = pkt_hdr->caplen + 64;
	sbuf.data = malloc(sbuf.alloced);
	if (sbuf.data == NULL)
		return (nmsg_res_memfail);
	sbuf.must_free_data = 1;
	
	buf_sz = nmsg__base__packet__pack_to_buffer(&packet, (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL)
		return (nmsg_res_memfail);

	*m = nmsg_message_from_raw_payload(NMSG_VENDOR_BASE_ID,
					   NMSG_VENDOR_BASE_PACKET_ID,
					   sbuf.data, buf_sz, &ts);
	return (nmsg_res_success);
}
