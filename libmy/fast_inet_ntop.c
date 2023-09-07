/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <string.h>

#include "fast_inet_ntop.h"

static char *
print_hex_uint16_t(uint16_t num, char *dst)
{
	static const char *hexchars = "0123456789abcdef";
	uint16_t ndx = 0;
	char *ptr = dst;

	if (num >= 0x1000) {
		ndx = 3;
	} else if (num >= 0x0100) {
		ndx = 2;
	} else if (num >= 0x0010) {
		ndx = 1;
	}

	do {
		uint32_t digit = num & 0xf;
		dst[ndx] = hexchars[digit];
		--ndx;
		ptr++;
		num >>= 4;
	} while (num != 0);
	return ptr;
}

static char numstr[100][2] = {
	 {'0','0'}, {'0','1'}, {'0','2'}, {'0','3'}, {'0','4'}, {'0','5'}, {'0','6'}, {'0','7'}, {'0','8'}, {'0','9'},
	 {'1','0'}, {'1','1'}, {'1','2'}, {'1','3'}, {'1','4'}, {'1','5'}, {'1','6'}, {'1','7'}, {'1','8'}, {'1','9'},
	 {'2','0'}, {'2','1'}, {'2','2'}, {'2','3'}, {'2','4'}, {'2','5'}, {'2','6'}, {'2','7'}, {'2','8'}, {'2','9'},
	 {'3','0'}, {'3','1'}, {'3','2'}, {'3','3'}, {'3','4'}, {'3','5'}, {'3','6'}, {'3','7'}, {'3','8'}, {'3','9'},
	 {'4','0'}, {'4','1'}, {'4','2'}, {'4','3'}, {'4','4'}, {'4','5'}, {'4','6'}, {'4','7'}, {'4','8'}, {'4','9'},
	 {'5','0'}, {'5','1'}, {'5','2'}, {'5','3'}, {'5','4'}, {'5','5'}, {'5','6'}, {'5','7'}, {'5','8'}, {'5','9'},
	 {'6','0'}, {'6','1'}, {'6','2'}, {'6','3'}, {'6','4'}, {'6','5'}, {'6','6'}, {'6','7'}, {'6','8'}, {'6','9'},
	 {'7','0'}, {'7','1'}, {'7','2'}, {'7','3'}, {'7','4'}, {'7','5'}, {'7','6'}, {'7','7'}, {'7','8'}, {'7','9'},
	 {'8','0'}, {'8','1'}, {'8','2'}, {'8','3'}, {'8','4'}, {'8','5'}, {'8','6'}, {'8','7'}, {'8','8'}, {'8','9'},
	 {'9','0'}, {'9','1'}, {'9','2'}, {'9','3'}, {'9','4'}, {'9','5'}, {'9','6'}, {'9','7'}, {'9','8'}, {'9','9'},
};

const char *
fast_inet4_ntop(const void *restrict src, char *restrict dst, socklen_t size)
{
	if (size < INET_ADDRSTRLEN || src == NULL || dst == NULL)
		return NULL;

	char *sptr = dst;
	const uint8_t *ipp = (const uint8_t *) src;
	for (size_t i = 0; i < 4; i++) {
		uint8_t ipb = ipp[i];
		const char *p;

		if (ipb >= 200) {
			*sptr++ = '2';
			ipb -= 200;
		} else if (ipb >= 100) {
			*sptr++ = '1';
			ipb -= 100;
		}

		/* Now have a value [0..99] */
		p = numstr[ipb];

		if (ipp[i] >= 10)
			*sptr++ = p[0];

		*sptr++ = p[1];

		if (i < 3)
			*sptr++ = '.';
	}

	*sptr = 0;
	return dst;
}

/* Modified from Paul Vixie's inet_ntop() under ISC license to avoid the performance hit of using sprintf() */
const char *
fast_inet6_ntop(const void *restrict src, char *restrict dst, socklen_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char *tp = dst;
	struct {
		int base, len;
	} best, cur;
	u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;
	const uint8_t *psrc = (const uint8_t *) src;

	if (size < INET6_ADDRSTRLEN || src == NULL || dst == NULL)
		return NULL;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in psrc[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i += 2)
		words[i / 2] = (psrc[i] << 8) | psrc[i + 1];
	best.base = -1;
	cur.base = -1;
	best.len = 0;
	cur.len = 0;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
			i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
			(best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!fast_inet4_ntop(psrc + 12, tp, size - (tp - dst)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		tp = print_hex_uint16_t(words[i], tp);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
						   (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((socklen_t)(tp - dst) > size) {
		errno = ENOSPC;
		return NULL;
	}
	return dst;
}

const char *
fast_inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size)
{
	switch(af) {
		case AF_INET:
			return fast_inet4_ntop(src, dst, size);
		case AF_INET6:
			return fast_inet6_ntop(src, dst, size);
		default:
			break;
	}

	return NULL;
}
