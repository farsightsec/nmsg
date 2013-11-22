/*
 * Copyright (c) 2011 by Farsight Security, Inc.
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

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Arc4 random number generator for OpenBSD.
 *
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

/* Import. */

#include "private.h"

/* Macros. */

#define	RANDOMDEV	"/dev/urandom"
#define KEYSIZE		128

/* Data structures. */

struct nmsg_random {
	uint8_t		i;
	uint8_t		j;
	uint8_t		s[256];
	int		arc4_count;
};

/* Forward. */

static void _nmsg_random_addrandom(nmsg_random_t, uint8_t *, size_t);
static void _nmsg_random_check_stir(nmsg_random_t r);
static void _nmsg_random_stir(nmsg_random_t);
static uint8_t _nmsg_random_getbyte(nmsg_random_t r);
static uint32_t _nmsg_random_getuint32(nmsg_random_t r);

/* Functions. */

nmsg_random_t
nmsg_random_init(void) {
	struct nmsg_random *r;
	int n;

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (NULL);

	for (n = 0; n < 256; n++)
		r->s[n] = n;
	r->i = 0;
	r->j = 0;

	_nmsg_random_stir(r);

	return (r);
}

void
nmsg_random_destroy(nmsg_random_t *r) {
	free(*r);
	*r = NULL;
}

static void
_nmsg_random_addrandom(nmsg_random_t r, uint8_t *dat, size_t datlen) {
	int n;
	uint8_t si;

	r->i--;
	for (n = 0; n < 256; n++) {
		r->i = (r->i + 1);
		si = r->s[r->i];
		r->j = (r->j + si + dat[n % datlen]);
		r->s[r->i] = r->s[r->j];
		r->s[r->j] = si;
	}
	r->j = r->i;
}

static void
_nmsg_random_check_stir(nmsg_random_t r) {
	if (r->arc4_count <= 0)
		_nmsg_random_stir(r);
}

static void
_nmsg_random_stir(nmsg_random_t r) {
	int done, fd, n;
	struct {
		struct timeval	tv;
		pid_t		pid;
		uint8_t		rnd[KEYSIZE];
	} rdat;

	fd = open(RANDOMDEV, O_RDONLY, 0);
	done = 0;
	if (fd >= 0) {
		if (read(fd, &rdat.rnd, KEYSIZE) == KEYSIZE)
			done = 1;
		(void)close(fd);
		_nmsg_random_addrandom(r, rdat.rnd, sizeof(rdat.rnd));
	} 
	if (!done) {
		(void)gettimeofday(&rdat.tv, NULL);
		rdat.pid = getpid();
		/* We'll just take whatever was on the stack too... */
		_nmsg_random_addrandom(r, (uint8_t *)&rdat, sizeof(rdat));
	}

	/*
	 * Throw away the first N bytes of output, as suggested in the
	 * paper "Weaknesses in the Key Scheduling Algorithm of RC4"
	 * by Fluher, Mantin, and Shamir.  N=1024 is based on
	 * suggestions in the paper "(Not So) Random Shuffles of RC4"
	 * by Ilya Mironov.
	 */
	for (n = 0; n < 1024; n++)
		(void)_nmsg_random_getbyte(r);
	r->arc4_count = 1600000;
}

static uint8_t
_nmsg_random_getbyte(nmsg_random_t r) {
	uint8_t si, sj;

	r->i = (r->i + 1);
	si = r->s[r->i];
	r->j = (r->j + si);
	sj = r->s[r->j];
	r->s[r->i] = sj;
	r->s[r->j] = si;

	return (r->s[(si + sj) & 0xff]);
}

static uint32_t
_nmsg_random_getuint32(nmsg_random_t r) {
	uint32_t val;

	val = _nmsg_random_getbyte(r) << 24;
	val |= _nmsg_random_getbyte(r) << 16;
	val |= _nmsg_random_getbyte(r) << 8;
	val |= _nmsg_random_getbyte(r);

	return (val);
}

uint32_t
nmsg_random_uint32(nmsg_random_t r) {
	uint32_t rnd;

	_nmsg_random_check_stir(r);
	rnd = _nmsg_random_getuint32(r);
	r->arc4_count -= 4;

	return (rnd);
}

void
nmsg_random_buf(nmsg_random_t r, uint8_t *buf, size_t n) {
	while (n--) {
		_nmsg_random_check_stir(r);
		buf[n] = _nmsg_random_getbyte(r);
		r->arc4_count--;
	}
}

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
uint32_t
nmsg_random_uniform(nmsg_random_t r, uint32_t upper_bound) {
	uint32_t rnd, min;

	if (upper_bound < 2)
		return (0);

#if (ULONG_MAX > 0xffffffffUL)
	min = 0x100000000UL % upper_bound;
#else
	/* Calculate (2**32 % upper_bound) avoiding 64-bit math */
	if (upper_bound > 0x80000000)
		min = 1 + ~upper_bound;		/* 2**32 - upper_bound */
	else {
		/* (2**32 - (x * 2)) % x == 2**32 % x when x <= 2**31 */
		min = ((0xffffffff - (upper_bound * 2)) + 1) % upper_bound;
	}
#endif

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		rnd = nmsg_random_uint32(r);
		if (rnd >= min)
			break;
	}

	return (rnd % upper_bound);
}
