#ifndef NMSG_FMA_H
#define NMSG_FMA_H

#include <sys/types.h>

#include <nmsg.h>

nmsg_fma
nmsg_fma_init(const char *, size_t, unsigned);

void
nmsg_fma_destroy(nmsg_fma *);

void *
nmsg_fma_alloc(nmsg_fma, size_t);

void
nmsg_fma_free(nmsg_fma, void *);

#endif
