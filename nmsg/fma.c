/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

/* Import. */

#include "nmsg_port.h"

#include <sys/mman.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"

/* Types. */

struct block_ptr {
	ISC_LINK(struct block_ptr)	link;
	void *				addr;
};

struct record {
	ssize_t				num, len;
};

struct nmsg_fma {
	ISC_LIST(struct block_ptr)	block_list;
	void *				current;
	size_t				block_size;
	unsigned			num_allocated;
	unsigned			debug_mode;
	char *				name;
};

/* Forward. */

static void *aligned_memory(size_t);
static void *fma_new_block(nmsg_fma_t);

/* Export. */

nmsg_fma_t
nmsg_fma_init(const char *name, size_t mb, unsigned debug) {
	nmsg_fma_t f;

	f = calloc(1, sizeof(*f));
	assert(f != NULL);
	ISC_LIST_INIT(f->block_list);
	f->block_size = mb * 1048576;
	f->debug_mode = debug;
	f->name = strdup(name);
	f->current = NULL;
	if (f->debug_mode >= 3)
		fprintf(stderr, "%s: %s %zu MB blocksize fma init'd\n",
			__func__, name, mb);

	return (f);
}

void
nmsg_fma_destroy(nmsg_fma_t *pf) {
	struct block_ptr *block, *blocknext;
	nmsg_fma_t f = *pf;

	block = ISC_LIST_HEAD(f->block_list);
	while (block != NULL) {
		blocknext = ISC_LIST_NEXT(block, link);
		ISC_LIST_UNLINK(f->block_list, block, link);
		if (munmap(block->addr, f->block_size) != 0)
			if (f->debug_mode >= 1)
				perror("munmap");
		free(block);
		block = blocknext;
	}
	free(f->name);
	free(f);
	*pf = NULL;
}

void *
nmsg_fma_alloc(nmsg_fma_t f, size_t size) {
	unsigned oldlen;
	struct record *rec = f->current;

	if (f->block_size - sizeof(struct record) < size)
		return (NULL);
	if (rec == NULL)
		rec = fma_new_block(f);
	if ((size_t) (rec->len + size) > (size_t) f->block_size)
		rec = fma_new_block(f);
	if (rec == NULL) {
		if (f->debug_mode >= 3)
			fprintf(stderr, "%s: %s %zu bytes alloc failed\n",
				__func__, f->name, size);
		return (NULL);
	}
	oldlen = rec->len;
	rec->num += 1;
	rec->len += size;
	if (f->debug_mode >= 4)
		fprintf(stderr, "%s: %s %zu bytes alloc'd, %zd total allocs\n",
			__func__, f->name, size, rec->num);
	return ((char *) rec) + oldlen;
}

void
nmsg_fma_free(nmsg_fma_t f, void *ptr) {
	struct block_ptr *block, *blocknext;
	struct record *rec = f->current;

	rec = (void *) ((long) ptr & ~(f->block_size - 1));
	rec->num -= 1;
	assert(rec->num >= 0);
	if (rec->num == 0) {
		if (munmap((void *) rec, f->block_size) != 0)
			if (f->debug_mode >= 1)
				perror("munmap");
		f->current = NULL;
		f->num_allocated -= 1;

		if (f->debug_mode >= 3)
			fprintf(stderr, "%s: freed %s block at %p@%#.zx, %u blocks total\n",
				__func__, f->name, rec, f->block_size,
				f->num_allocated);

		block = ISC_LIST_HEAD(f->block_list);
		while (block != NULL) {
			blocknext = ISC_LIST_NEXT(block, link);
			if (rec == block->addr) {
				ISC_LIST_UNLINK(f->block_list, block, link);
				free(block);
				rec = NULL;
				break;
			}
			block = blocknext;
		}
	}
	if (f->debug_mode >= 4)
		fprintf(stderr, "%s: %s ptr freed, %zd total allocs\n",
			__func__, f->name, rec ? rec->num : 0);
}

/* Private. */

static void *
aligned_memory(size_t sz) { /* sz must be a power of 2 */
	char *addr, *aligned;
	size_t head, tail;

	addr = mmap(NULL, 2*sz, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED)
		return (MAP_FAILED);

	aligned = ((char *) ((long) addr & ~(sz - 1))) + sz;
	
	head = aligned - addr;
	tail = sz - (aligned - addr);
	if (head > 0 && munmap(addr, head) != 0)
		return (MAP_FAILED);
	if (tail > 0 && munmap(aligned + sz, tail) != 0)
		return (MAP_FAILED);

	return ((void *) aligned);
}

static void *
fma_new_block(nmsg_fma_t f) {
	struct block_ptr *block;
	struct record *rec;

	block = malloc(sizeof *block);
	assert(block != NULL);
	ISC_LINK_INIT(block, link);
	if ((block->addr = aligned_memory(f->block_size)) == MAP_FAILED) {
		if (f->debug_mode >= 1) {
			perror("aligned_memory");
			assert(0);
		}
		free(block);
		return (NULL);
	}
	ISC_LIST_APPEND(f->block_list, block, link);
	f->num_allocated += 1;
	rec = f->current = block->addr;
	rec->num = 0;
	rec->len = sizeof(struct nmsg_fma);

	if (f->debug_mode >= 3)
		fprintf(stderr, "%s: allocated %s block at %p@%#.zx, %u blocks total\n",
			__func__, f->name, block->addr, f->block_size,
			f->num_allocated);

	return (rec);
}
