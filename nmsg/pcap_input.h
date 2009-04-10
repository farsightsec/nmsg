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

#ifndef NMSG_PCAP_H
#define NMSG_PCAP_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/pcap.h
 * \brief libpcap interface
 */

/***
 *** Imports
 ***/

#include <nmsg.h>
#include <pcap.h>

/***
 *** Functions
 ***/

nmsg_pcap
nmsg_pcap_input_open(pcap_t *phandle);
/*%<
 * Initialize a new nmsg_pcap input from a libpcap source.
 *
 * Requires:
 *
 * \li	'phandle' is a valid pcap_t handle
 *	(e.g., acquired from pcap_open_offline())
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_res
nmsg_pcap_input_close(nmsg_pcap *pcap);
/*%<
 * XXX
 */

nmsg_res
nmsg_pcap_input_next(nmsg_pcap pcap, struct nmsg_ipdg *dg);
/*%<
 * XXX
 */

nmsg_res
nmsg_pcap_input_setfilter(nmsg_pcap pcap, const char *bpfstr);
/*%<
 * Set the bpf filter on an nmsg_pcap object.
 *
 * Requires:
 *
 * \li	'pcap' is an initialized nmsg_pcap object.
 *
 * \li	'bpfstr' is a valid bpf filter expression that will be passed to
 *	pcap_compile().
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 */

#endif /* NMSG_PCAP_H */
