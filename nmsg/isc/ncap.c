/* ncap nmsg message module */

/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#define MSGTYPE_NCAP_ID		1
#define MSGTYPE_NCAP_NAME	"ncap"

/* Import. */

#include "nmsg_port.h"
#include "nmsg_port_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <wdns.h>

#include "ncap.pb-c.c"

/* Exported via module context. */

static nmsg_res
ncap_msg_load(nmsg_message_t m, void **msg_clos);

static nmsg_res
ncap_msg_fini(nmsg_message_t m, void *msg_clos);

static nmsg_res
ncap_ipdg_to_payload(void *, const struct nmsg_ipdg *, uint8_t **pay, size_t *);

static NMSG_MSGMOD_FIELD_PRINTER(ncap_print_payload);

static NMSG_MSGMOD_FIELD_GETTER(ncap_get_srcip);
static NMSG_MSGMOD_FIELD_GETTER(ncap_get_dstip);
static NMSG_MSGMOD_FIELD_GETTER(ncap_get_srcport);
static NMSG_MSGMOD_FIELD_GETTER(ncap_get_dstport);

/* Data. */

struct nmsg_msgmod_field ncap_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "ltype"
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "srcip",
		.get = ncap_get_srcip,
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "dstip",
		.get = ncap_get_dstip,
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "lint0",
		.flags = NMSG_MSGMOD_FIELD_HIDDEN,
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "lint1",
		.flags = NMSG_MSGMOD_FIELD_HIDDEN,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "srcport",
		.get = ncap_get_srcport,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "dstport",
		.get = ncap_get_dstport,
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "payload",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED,
		.print = ncap_print_payload
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	.msgver = NMSG_MSGMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { MSGTYPE_NCAP_ID, MSGTYPE_NCAP_NAME },

	.msg_load = ncap_msg_load,
	.msg_fini = ncap_msg_fini,
	.pbdescr = &nmsg__isc__ncap__descriptor,
	.fields = ncap_fields,
	.ipdg_to_payload = ncap_ipdg_to_payload
};

/* Forward. */

static nmsg_res ncap_pbuf_inet_ntop(ProtobufCBinaryData *bdata, char *str);

static nmsg_res
ncap_print_udp(nmsg_strbuf_t, const char *srcip, const char *dstip,
	       uint16_t srcport, uint16_t dstport,
	       const u_char *payload, size_t paylen, const char *el);

/* Private. */

struct ncap_priv {
	bool			has_srcip;
	bool			has_dstip;
	bool			has_srcport;
	bool			has_dstport;
	uint32_t		srcport;
	uint32_t		dstport;
	ProtobufCBinaryData	srcip;
	ProtobufCBinaryData	dstip;
	struct nmsg_ipdg	dg;
};

static nmsg_res
ncap_msg_load(nmsg_message_t m, void **msg_clos) {
	Nmsg__Isc__Ncap *ncap;
	const struct ip *ip;
	const struct ip6_hdr *ip6;
	const struct udphdr *udp;
	struct ncap_priv *p;
	unsigned etype;

	ncap = (Nmsg__Isc__Ncap *) nmsg_message_get_payload(m);
	if (ncap == NULL)
		return (nmsg_res_failure);

	*msg_clos = p = calloc(1, sizeof(struct ncap_priv));
	if (p == NULL)
		return (nmsg_res_memfail);

	/* source and destination IPs */
	switch (ncap->type) {
	case NMSG__ISC__NCAP_TYPE__IPV4:
		etype = ETHERTYPE_IP;
		nmsg_ipdg_parse(&p->dg, etype, ncap->payload.len, ncap->payload.data);
		ip = (const struct ip *) p->dg.network;
		p->has_srcip = true;
		p->has_dstip = true;
		p->srcip.len = 4;
		p->dstip.len = 4;
		p->srcip.data = (uint8_t *) &ip->ip_src;
		p->dstip.data = (uint8_t *) &ip->ip_dst;
		break;
	case NMSG__ISC__NCAP_TYPE__IPV6:
		etype = ETHERTYPE_IPV6;
		nmsg_ipdg_parse(&p->dg, etype, ncap->payload.len, ncap->payload.data);
		ip6 = (const struct ip6_hdr *) p->dg.network;
		p->has_srcip = true;
		p->has_dstip = true;
		p->srcip.len = 16;
		p->dstip.len = 16;
		p->srcip.data = (uint8_t *) &ip6->ip6_src;
		p->dstip.data = (uint8_t *) &ip6->ip6_dst;
		break;
	case NMSG__ISC__NCAP_TYPE__Legacy:
		break;
	}

	/* source and destination ports */
	switch (ncap->type) {
	case NMSG__ISC__NCAP_TYPE__IPV4:
	case NMSG__ISC__NCAP_TYPE__IPV6:
		switch (p->dg.proto_transport) {
		case IPPROTO_UDP:
			udp = (const struct udphdr *) p->dg.transport;
			p->has_srcport = true;
			p->has_dstport = true;
			p->srcport = ntohs(udp->uh_sport);
			p->dstport = ntohs(udp->uh_dport);
			break;
		}
		break;
	case NMSG__ISC__NCAP_TYPE__Legacy:
		switch (ncap->ltype) {
		case NMSG__ISC__NCAP_LEGACY_TYPE__UDP:
		case NMSG__ISC__NCAP_LEGACY_TYPE__TCP:
			if (ncap->has_lint0) {
				p->has_srcport = true;
				p->srcport = ncap->lint0;
			}
			if (ncap->has_lint1) {
				p->has_dstport = true;
				p->dstport = ncap->lint1;
			}
		case NMSG__ISC__NCAP_LEGACY_TYPE__ICMP:
			break;
		}
	}

	return (nmsg_res_success);
}

static nmsg_res
ncap_msg_fini(nmsg_message_t m, void *msg_clos) {
	free(msg_clos);
	return (nmsg_res_success);
}

static nmsg_res
ncap_get_srcip(nmsg_message_t m,
		 struct nmsg_msgmod_field *field,
		 unsigned val_idx,
		 void **data,
		 size_t *len,
		 void *msg_clos)
{
	Nmsg__Isc__Ncap *ncap;
	struct ncap_priv *p = msg_clos;

	ncap = (Nmsg__Isc__Ncap *) nmsg_message_get_payload(m);
	if (ncap == NULL)
		return (nmsg_res_failure);

	if (val_idx == 0) {
		switch (ncap->type) {
		case NMSG__ISC__NCAP_TYPE__IPV4:
		case NMSG__ISC__NCAP_TYPE__IPV6:
			*data = p->srcip.data;
			if (len)
				*len = p->srcip.len;
			break;
		case NMSG__ISC__NCAP_TYPE__Legacy:
			if (ncap->has_srcip) {
				*data = ncap->srcip.data;
				if (len)
					*len = ncap->srcip.len;
			}
			break;
		}

		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

static nmsg_res
ncap_get_dstip(nmsg_message_t m,
		 struct nmsg_msgmod_field *field,
		 unsigned val_idx,
		 void **data,
		 size_t *len,
		 void *msg_clos)
{
	Nmsg__Isc__Ncap *ncap;
	struct ncap_priv *p = msg_clos;

	ncap = (Nmsg__Isc__Ncap *) nmsg_message_get_payload(m);
	if (ncap == NULL)
		return (nmsg_res_failure);

	if (val_idx == 0) {
		switch (ncap->type) {
		case NMSG__ISC__NCAP_TYPE__IPV4:
		case NMSG__ISC__NCAP_TYPE__IPV6:
			*data = p->dstip.data;
			if (len)
				*len = p->dstip.len;
			break;
		case NMSG__ISC__NCAP_TYPE__Legacy:
			if (ncap->has_dstip) {
				*data = ncap->dstip.data;
				if (len)
					*len = ncap->dstip.len;
			}
			break;
		}

		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

static nmsg_res
ncap_get_srcport(nmsg_message_t m,
		 struct nmsg_msgmod_field *field,
		 unsigned val_idx,
		 void **data,
		 size_t *len,
		 void *msg_clos)
{
	struct ncap_priv *p = msg_clos;

	if (val_idx == 0 && p->has_srcport) {
		*data = &p->srcport;
		if (len)
			*len = sizeof(p->srcport);

		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

static nmsg_res
ncap_get_dstport(nmsg_message_t m,
		 struct nmsg_msgmod_field *field,
		 unsigned val_idx,
		 void **data,
		 size_t *len,
		 void *msg_clos)
{
	struct ncap_priv *p = msg_clos;

	if (val_idx == 0 && p->has_dstport) {
		*data = &p->dstport;
		if (len)
			*len = sizeof(p->dstport);

		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

static nmsg_res
ncap_pbuf_inet_ntop(ProtobufCBinaryData *bdata, char *str) {
	socklen_t strsz = INET6_ADDRSTRLEN;

	if (bdata->len == 4) {
		if (inet_ntop(AF_INET, bdata->data, str, strsz) == NULL)
			return (nmsg_res_failure);
	} else if (bdata->len == 16) {
		if (inet_ntop(AF_INET6, bdata->data, str, strsz) == NULL)
			return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
ncap_print_udp(nmsg_strbuf_t sb, const char *srcip, const char *dstip,
	       uint16_t srcport, uint16_t dstport,
	       const u_char *payload, size_t paylen, const char *el)
{
	nmsg_res res;

	if (payload == NULL)
		return (nmsg_res_failure);
	res = nmsg_strbuf_append(sb, "[%s].%hu [%s].%hu udp [%u]%s",
				 srcip, srcport, dstip, dstport, paylen, el);
	if (res != nmsg_res_success)
		return (nmsg_res_failure);

	if (srcport == 53 || srcport == 5353 ||
	    dstport == 53 || dstport == 5353)
	{
		char *s;
		wdns_message_t m;
		wdns_msg_status status;

		status = wdns_parse_message(&m, payload, paylen);
		if (status != wdns_msg_success)
			return (nmsg_res_failure);
		s = wdns_message_to_str(&m);
		if (s == NULL)
			return (nmsg_res_memfail);
		nmsg_strbuf_append(sb, "%s", s);
		free(s);

		wdns_clear_message(&m);
	}
	if (res != nmsg_res_success)
		return (nmsg_res_failure);
	nmsg_strbuf_append(sb, "\n");

	return (nmsg_res_success);
}

static nmsg_res
ncap_print_payload(nmsg_message_t msg,
		   struct nmsg_msgmod_field *field __attribute__((unused)),
		   void *ptr __attribute__((unused)),
		   nmsg_strbuf_t sb,
		   const char *endline)
{
	Nmsg__Isc__Ncap *ncap;
	char dstip[INET6_ADDRSTRLEN];
	char srcip[INET6_ADDRSTRLEN];
	const char *err_str = "unknown";
	const struct ip *ip;
	const struct ip6_hdr *ip6;
	const struct udphdr *udp;
	nmsg_res res;
	struct nmsg_ipdg dg;
	unsigned etype;

	ncap = (Nmsg__Isc__Ncap *) nmsg_message_get_payload(msg);
	if (ncap == NULL)
		return (nmsg_res_failure);

	dstip[0] = '\0';
	srcip[0] = '\0';

	res = nmsg_strbuf_append(sb, "payload:%s", endline);
	if (res != nmsg_res_success)
		return (res);

	/* parse header fields */
	switch (ncap->type) {
	case NMSG__ISC__NCAP_TYPE__IPV4:
		etype = ETHERTYPE_IP;
		nmsg_ipdg_parse(&dg, etype, ncap->payload.len, ncap->payload.data);
		ip = (const struct ip *) dg.network;
		inet_ntop(AF_INET, &ip->ip_src.s_addr, srcip, sizeof(srcip));
		inet_ntop(AF_INET, &ip->ip_dst.s_addr, dstip, sizeof(dstip));
		break;
	case NMSG__ISC__NCAP_TYPE__IPV6:
		etype = ETHERTYPE_IPV6;
		nmsg_ipdg_parse(&dg, etype, ncap->payload.len, ncap->payload.data);
		ip6 = (const struct ip6_hdr *) dg.network;
		inet_ntop(AF_INET6, ip6->ip6_src.s6_addr, srcip, sizeof(srcip));
		inet_ntop(AF_INET6, ip6->ip6_dst.s6_addr, dstip, sizeof(dstip));
		break;
	case NMSG__ISC__NCAP_TYPE__Legacy:
		if (ncap->has_srcip == 0) {
			err_str = "legacy ncap payload missing srcip field";
			goto err;
		}
		if (ncap->has_dstip == 0) {
			err_str = "legacy ncap payload missing dstip field";
			goto err;
		}
		if (ncap_pbuf_inet_ntop(&ncap->srcip, srcip) == nmsg_res_failure)
		{
			err_str = "unable to decode legacy ncap srcip field";
			goto err;
		}
		if (ncap_pbuf_inet_ntop(&ncap->dstip, dstip) == nmsg_res_failure)
		{
			err_str = "unable to decode legacy ncap dstip field";
			goto err;
		}
		break;
	default:
		goto unknown_ncap_type;
		break;
	}

	/* parse payload */
	switch (ncap->type) {
	case NMSG__ISC__NCAP_TYPE__IPV4:
	case NMSG__ISC__NCAP_TYPE__IPV6:
		switch (dg.proto_transport) {
		case IPPROTO_UDP:
			udp = (const struct udphdr *) dg.transport;
			res = ncap_print_udp(sb, srcip, dstip,
					     ntohs(udp->uh_sport),
					     ntohs(udp->uh_dport),
					     dg.payload, dg.len_payload, endline);
			if (res != nmsg_res_success) {
				err_str = "payload parse failed";
				goto err;
			}
			break;
		}
		break;
	case NMSG__ISC__NCAP_TYPE__Legacy:
		switch (ncap->ltype) {
		case NMSG__ISC__NCAP_LEGACY_TYPE__UDP:
			if (ncap->has_lint0 == 0) {
				err_str = "legacy ncap payload missing lint0 field";
				goto err;
			}
			if (ncap->has_lint1 == 0) {
				err_str = "legacy ncap payload missing lint1 field";
				goto err;
			}
			res = ncap_print_udp(sb, srcip, dstip,
					     ncap->lint0, ncap->lint1,
					     ncap->payload.data,
					     ncap->payload.len, endline);
			if (res != nmsg_res_success) {
				err_str = "legacy payload parse failed";
				goto err;
			}
			break;
		case NMSG__ISC__NCAP_LEGACY_TYPE__TCP:
		case NMSG__ISC__NCAP_LEGACY_TYPE__ICMP:
			res = nmsg_strbuf_append(sb, "<ERROR: unhandled legacy ncap type %u>%s",
						 ncap->ltype, endline);
			return (res);
			break;
		}
		break;
	default:
		goto unknown_ncap_type;
		break;
	}

	return (nmsg_res_success);

err:
	res = nmsg_strbuf_append(sb, "<ERROR: %s>%s", err_str, endline);
	return (res);

unknown_ncap_type:
	res = nmsg_strbuf_append(sb, "<ERROR: unknown ncap type %u>%s",
				 ncap->type, endline);
	return (res);
}

static nmsg_res
ncap_ipdg_to_payload(void *clos __attribute__((unused)),
		     const struct nmsg_ipdg *dg,
		     uint8_t **pbuf, size_t *sz)
{
	Nmsg__Isc__Ncap nc;
	size_t estsz;

	/* initialize in-memory ncap message */
	nmsg__isc__ncap__init(&nc);

	/* set type */
	switch (dg->proto_network) {
	case PF_INET:
		nc.type = NMSG__ISC__NCAP_TYPE__IPV4;
		break;
	case PF_INET6:
		nc.type = NMSG__ISC__NCAP_TYPE__IPV6;
		break;
	default:
		return (nmsg_res_parse_error);
	}

	/* set payload */
	nc.payload.data = (uint8_t *) dg->network;
	nc.payload.len = dg->len_network;

	/* serialize ncap payload */
	estsz = nc.payload.len + 64 /* ad hoc */;
	*pbuf = malloc(estsz);
	if (*pbuf == NULL)
		return (nmsg_res_memfail);
	*sz = nmsg__isc__ncap__pack(&nc, *pbuf);

	return (nmsg_res_pbuf_ready);
}

/*! \file nmsg/isc/ncap.c
 * \brief ISC "ncap" message type.
 *
 * This message type is meant to carry reassembled IP datagrams. It contains
 * legacy fields which enable messages generated by libncap to be converted to
 * NMSG ncap payloads.
 *
 * This module does not support conversion from presentation-form-to-NMSG
 * payload.
 *
 * <b>ncap message fields.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Type </b></td>
<td><b> Required </b></td>
<td><b> Repeated </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> type </td>
<td> enum NcapType </td>
<td> yes </td>
<td> no </td>
<td> Type of ncap payload </td>
</tr>

<tr>
<td> payload </td>
<td> bytes </td>
<td> yes </td>
<td> no </td>
<td> ncap payload </td>
</tr>

<tr>
<td> ltype </td>
<td> enum NcapLegacyType </td>
<td> no </td>
<td> no </td>
<td> If legacy ncap, type of legacy ncap payload </td>
</tr>

<tr>
<td> srcip </td>
<td> IP address </td>
<td> no </td>
<td> no </td>
<td> If legacy ncap, source IP address </td>
</tr>

<tr>
<td> dstip </td>
<td> IP address </td>
<td> no </td>
<td> no </td>
<td> If legacy ncap, destination IP address </td>
</tr>

<tr>
<td> lint0 </td>
<td> uint32 </td>
<td> no </td>
<td> no </td>
<td> If legacy ncap, ltype-specific integer </td>
</tr>

<tr>
<td> lint1 </td>
<td> uint32 </td>
<td> no </td>
<td> no </td>
<td> If legacy ncap, ltype-specific integer </td>
</tr>

</table>

 * <b>enum NcapType values.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Value </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> IPV4 </td>
<td> 0 </td>
<td> ncap payload is an IPv4 datagram </td>
</tr>

<tr>
<td> IPV6 </td>
<td> 1 </td>
<td> ncap payload is an IPv4 datagram </td>
</tr>

<tr>
<td> Legacy </td>
<td> 2 </td>
<td> ncap payload is a legacy NCAP application layer payload </td>
</tr>

</table>

 * <b>enum NcapLegacyType values.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Value </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> UDP </td>
<td> 0 </td>
<td> NCAP legacy payload is a UDP payload; lint0 is UDP source port;
	lint1 is UDP destination port </td>
</tr>

<tr>
<td> TCP </td>
<td> 1 </td>
<td> NCAP legacy payload is a TCP payload; lint0 is TCP source port;
	lint1 is TCP destination port </td>
</tr>

<tr>
<td> ICMP </td>
<td> 2 </td>
<td> NCAP legacy payload is an ICMP payload; lint0 is ICMP type;
	lint1 is ICMP code </td>
</tr>

</table>
 */
