/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_SPLIT_INTERNAL_H
#define USTR_SPLIT_INTERNAL_H 1

#ifndef USTR_MAIN_H
# error " You should have already included ustr-main.h, or just include ustr.h"
#endif

USTR_CONF_e_PROTO
struct Ustr *ustrp__split_buf(struct Ustr_pool *, const struct Ustr *, size_t *,
                              const void *, size_t, struct Ustr *,unsigned int);

USTR_CONF_e_PROTO
struct Ustr *ustrp__split_spn_chrs(struct Ustr_pool *, const struct Ustr *, size_t *, 
                                   const char *, size_t, struct Ustr * , unsigned int);

#endif
