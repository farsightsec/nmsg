/*
 * Copyright (c) 2007, 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#include "nmsg_port.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nmsg.h>

#include "dump_dns.h"

#ifndef HAVE_LIBBIND

nmsg_res
dump_dns(nmsg_strbuf_t sb, const u_char *payload __attribute__((unused)),
	 size_t paylen __attribute__((unused)), const char *el)
{
	return (nmsg_strbuf_append(sb, "NO LIBBIND%s", el));
}

#else

static const char *_res_opcodes[] = {
	"QUERY",
	"IQUERY",
	"CQUERYM",
	"CQUERYU",
	"NOTIFY",
	"UPDATE",
	"6",
	"7",
	"8",
	"9",
	"10",
	"11",
	"12",
	"13",
	"ZONEINIT",
	"ZONEREF",
};

nmsg_res
dump_dns(nmsg_strbuf_t sb, const u_char *payload, size_t paylen, const char *el)
{
	unsigned opcode, rcode, id;
	const char *sep, *rcp;
	char rct[100];
	ns_msg msg;

	nmsg_strbuf_append(sb, "dns ");	
	if (ns_initparse(payload, paylen, &msg) < 0) {
		/* XXX this code is reentrant, strerror() is not */
		nmsg_strbuf_append(sb, "libbind error: %s", strerror(errno));
		return (nmsg_res_success);
	}
	opcode = ns_msg_getflag(msg, ns_f_opcode);
	rcode = ns_msg_getflag(msg, ns_f_rcode);
	id = ns_msg_id(msg);
	if ((rcp = dump_dns_rcode(rcode)) == NULL) {
		sprintf(rct, "CODE%u", rcode);
		rcp = rct;
	}
	nmsg_strbuf_append(sb, "%s,%s,%u", _res_opcodes[opcode], rcp, id);
	sep = ",";
#define FLAG(t,f) if (ns_msg_getflag(msg, f)) { \
			nmsg_strbuf_append(sb, "%s%s", sep, t); \
			sep = "|"; \
		  }
	FLAG("qr", ns_f_qr);
	FLAG("aa", ns_f_aa);
	FLAG("tc", ns_f_tc);
	FLAG("rd", ns_f_rd);
	FLAG("ra", ns_f_ra);
	FLAG("z", ns_f_z);
	FLAG("ad", ns_f_ad);
	FLAG("cd", ns_f_cd);
#undef FLAG
	dump_dns_sect(sb, &msg, ns_s_qd, el);
	dump_dns_sect(sb, &msg, ns_s_an, el);
	dump_dns_sect(sb, &msg, ns_s_ns, el);
	dump_dns_sect(sb, &msg, ns_s_ar, el);

	return (nmsg_res_success);
}

nmsg_res
dump_dns_sect(nmsg_strbuf_t sb, ns_msg *msg, ns_sect sect, const char *el) {
	int rrnum, rrmax;
	const char *sep;
	ns_rr rr;

	rrmax = ns_msg_count(*msg, sect);
	if (rrmax == 0) {
		return (nmsg_strbuf_append(sb, " 0"));
	}
	nmsg_strbuf_append(sb, "%s%d", el, rrmax);
	sep = " ";
	for (rrnum = 0; rrnum < rrmax; rrnum++) {
		if (ns_parserr(msg, sect, rrnum, &rr)) {
			char errbuf[256];
			strerror_r(errno, errbuf, sizeof(errbuf));
			nmsg_strbuf_append(sb, "%s%s", errbuf, el);
			return (nmsg_res_success);
		}
		nmsg_strbuf_append(sb, "%s", sep);
		dump_dns_rr(sb, msg, &rr, sect);
		sep = el;
	}

	return (nmsg_res_success);
}

nmsg_res
dump_dns_rr(nmsg_strbuf_t sb, ns_msg *msg, ns_rr *rr, ns_sect sect) {
	char ct[100], tt[100];
	const char *cp, *tp;
	unsigned class, type;

	class = ns_rr_class(*rr);
	type = ns_rr_type(*rr);
	if ((cp = dump_dns_class(class)) == NULL) {
		sprintf(ct, "CLASS%u", class);
		cp = ct;
	}
	if ((tp = dump_dns_type(type)) == NULL) {
		sprintf(tt, "TYPE%u", type);
		tp = tt;
	}
	nmsg_strbuf_append(sb, "%s,%s,%s", ns_rr_name(*rr), cp, tp);
	if (sect == ns_s_qd)
		return (nmsg_res_success);

	nmsg_strbuf_append(sb, ",%lu", (u_long) ns_rr_ttl(*rr));
	return (dump_dns_rd(sb, ns_msg_base(*msg), ns_msg_end(*msg), type,
			    ns_rr_rdata(*rr), ns_rr_rdlen(*rr)));
}

nmsg_res
dump_dns_rd(nmsg_strbuf_t sb, const u_char *msg, const u_char *eom,
	    unsigned type, const u_char *rdata, unsigned rdlen)
{
	const char uncompress_error[] = "..name.error..";
	char buf[NS_MAXDNAME];
	const char *sep;
	uint32_t soa[5];
	uint16_t mx;
	int n;

	switch (type) {
	case ns_t_soa:
		n = ns_name_uncompress(msg, eom, rdata, buf, sizeof(buf));
		if (n < 0)
			strcpy(buf, uncompress_error);
		nmsg_strbuf_append(sb, ",%s", buf);
		rdata += n;
		n = ns_name_uncompress(msg, eom, rdata, buf, sizeof(buf));
		if (n < 0)
			strcpy(buf, uncompress_error);
		nmsg_strbuf_append(sb, ",%s", buf);
		rdata += n;
		if (eom - rdata < 5*NS_INT32SZ)
			goto error;
		for (n = 0; n < 5; n++)
			NS_GET32(soa[n], rdata);
		sprintf(buf, "%u,%u,%u,%u,%u",
			soa[0], soa[1], soa[2], soa[3], soa[4]);
		break;
	case ns_t_a:
		inet_ntop(AF_INET, rdata, buf, sizeof(buf));
		break;
	case ns_t_aaaa:
		inet_ntop(AF_INET6, rdata, buf, sizeof(buf));
		break;
	case ns_t_txt:
		nmsg_strbuf_append(sb, ",[");
		sep = "";
		while (rdlen > 0) {
			unsigned txtl = *rdata++;

			rdlen--;
			if (txtl > rdlen) {
				nmsg_strbuf_append(sb, "?");
				break;
			}
			nmsg_strbuf_append(sb, sep);
			sep = ",";
			nmsg_strbuf_append(sb, "\"");
			while (txtl-- > 0) {
				int ch = *rdata++;

				rdlen--;
				if (isascii(ch) && isprint(ch)) {
					if (strchr("],\\\"\040", ch) != NULL)
						nmsg_strbuf_append(sb, "\\");
					nmsg_strbuf_append(sb, "%c", ch);
				} else {
					nmsg_strbuf_append(sb, "\\%03o", ch);
				}
			}
			nmsg_strbuf_append(sb, "\"");
		}
		nmsg_strbuf_append(sb, "]");
		buf[0] = '\0';
		break;
	case ns_t_mx:
		NS_GET16(mx, rdata);
		nmsg_strbuf_append(sb, ",%u", mx);
		/* FALLTHROUGH */
	case ns_t_ns:
	case ns_t_ptr:
	case ns_t_cname:
		n = ns_name_uncompress(msg, eom, rdata, buf, sizeof(buf));
		if (n < 0)
			strcpy(buf, uncompress_error);
		break;
	default:
 error:
		sprintf(buf, "[%u]", rdlen);
	}
	if (buf[0] != '\0') {
		nmsg_strbuf_append(sb, ",%s", buf);
	}

	return (nmsg_res_success);
}

const char *
dump_dns_rcode(unsigned rcode) {
	switch (rcode) {
	case ns_r_noerror:	return "NOERROR";
	case ns_r_formerr:	return "FORMERR";
	case ns_r_servfail:	return "SERVFAIL";
	case ns_r_nxdomain:	return "NXDOMAIN";
	case ns_r_notimpl:	return "NOTIMPL";
	case ns_r_refused:	return "REFUSED";
	case ns_r_yxdomain:	return "YXDOMAIN";
	case ns_r_yxrrset:	return "YXRRSET";
	case ns_r_nxrrset:	return "NXRRSET";
	case ns_r_notauth:	return "NOTAUTH";
	case ns_r_notzone:	return "NOTZONE";
	default:		break;
	}
	return (NULL);
}

const char *
dump_dns_type(unsigned type) {
	switch (type) {
	case ns_t_a:		return "A";
	case ns_t_ns:		return "NS";
	case ns_t_cname:	return "CNAME";
	case ns_t_soa:		return "SOA";
	case ns_t_mb:		return "MB";
	case ns_t_mg:		return "MG";
	case ns_t_mr:		return "MR";
	case ns_t_null:		return "NULL";
	case ns_t_wks:		return "WKS";
	case ns_t_ptr:		return "PTR";
	case ns_t_hinfo:	return "HINFO";
	case ns_t_minfo:	return "MINFO";
	case ns_t_mx:		return "MX";
	case ns_t_txt:		return "TXT";
	case ns_t_rp:		return "RP";
	case ns_t_afsdb:	return "AFSDB";
	case ns_t_x25:		return "X25";
	case ns_t_isdn:		return "ISDN";
	case ns_t_rt:		return "RT";
	case ns_t_nsap:		return "NSAP";
	case ns_t_nsap_ptr:	return "NSAP_PTR";
	case ns_t_sig:		return "SIG";
	case ns_t_key:		return "KEY";
	case ns_t_px:		return "PX";
	case ns_t_gpos:		return "GPOS";
	case ns_t_aaaa:		return "AAAA";
	case ns_t_loc:		return "LOC";
	case ns_t_axfr:		return "AXFR";
	case ns_t_mailb:	return "MAILB";
	case ns_t_maila:	return "MAILA";
	case ns_t_any:		return "ANY";
	default:		break;
	}
	return NULL;
}

const char *
dump_dns_class(unsigned class) {
	switch (class) {
	case ns_c_in:		return "IN";
	case ns_c_hs:		return "HS";
	case ns_c_any:		return "ANY";
	default:		break;
	}
	return NULL;
}

#endif /* HAVE_LIBBIND */
