/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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

static argv_t args[] = {
	{ 'h',	"help",
		ARGV_BOOL,
		&ctx.help,
		NULL,
		"display help text and exit" },

	{ 'd',	"debug",
		ARGV_INCR,
		&ctx.debug,
		NULL,
		"increment debugging level" },

	{ 'V', "vendor",
		ARGV_CHAR_P,
		&ctx.vname,
		"vendor",
		"vendor" },

	{ 'T', "msgtype",
		ARGV_CHAR_P,
		&ctx.mname,
		"msgtype",
		"message type" },

	{ 'F', "flush",
		ARGV_BOOL,
		&ctx.flush,
		NULL,
		"flush outputs after every bufferable write" },

	{ 'e', "endline",
		ARGV_CHAR_P,
		&ctx.endline,
		"endline",
		"continuation separator" },

	{ 'm', "mtu",
		ARGV_INT,
		&ctx.mtu,
		"mtu",
		"MTU for datagram socket outputs" },

	{ 'c',	"count",
		ARGV_INT,
		&ctx.count,
		"count",
		"stop or reopen after count payloads output" },

	{ 't',	"interval",
		ARGV_INT,
		&ctx.interval,
		"secs",
		"stop or reopen after secs have elapsed" },

	{ 'k',	"kicker",
		ARGV_CHAR_P,
		&ctx.kicker,
		"cmd",
		"make -c, -t continuous; run cmd on new files" },

	{ 'b',	"bpf",
		ARGV_CHAR_P,
		&ctx.bpfstr,
		"filter",
		"filter pcap inputs with this bpf" },

	{ 'r', "readnmsg",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_nmsg,
		"file",
		"read nmsg data from file" },

	{ 'f', "readpres",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_pres,
		"file",
		"read pres format data from file" },

	{ 'l', "readsock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_sock,
		"so",
		"read nmsg data from socket (addr/port)" },

	{ 'C', "readchan",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_channel,
		"channel",
		"read nmsg data from socket(s)" },

	{ 'p',	"readpcap",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_pcapfile,
		"file",
		"read pcap data from file" },

	{ 'i',	"readif",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_pcapif,
		"if[+][,snap]",
		"read pcap data from interface ('+' = promisc)" },

	{ 'w', "writenmsg",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_nmsg,
		"file",
		"write nmsg data to file" },

	{ 'o', "writepres",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_pres,
		"file",
		"write pres format data to file" },

	{ 's', "writesock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_sock,
		"so[,r[,f]]",
		"write nmsg data to socket (addr/port)" },

	{ 'z', "zlibout",
		ARGV_BOOL,
		&ctx.zlibout,
		NULL,
		"compress nmsg output" },

	{ '\0', "mirror",
		ARGV_BOOL,
		&ctx.mirror,
		NULL,
		"mirror payloads across data outputs" },

	{ '\0', "unbuffered",
		ARGV_BOOL,
		&ctx.unbuffered,
		NULL,
		"don't buffer payloads on nmsg socket outputs" },

	{ '\0',	"setsource",
		ARGV_CHAR_P,
		&ctx.set_source_str,
		"sonum",
		"set source to this value" },

	{ '\0',	"setoperator",
		ARGV_CHAR_P,
		&ctx.set_operator_str,
		"opname",
		"set operator to this value" },

	{ '\0',	"setgroup",
		ARGV_CHAR_P,
		&ctx.set_group_str,
		"grname",
		"set group to this value" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};
