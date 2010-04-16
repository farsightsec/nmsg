/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_POOL_H
#define USTR_POOL_H 1

#ifndef USTR_MAIN_H
#error " You should have already included ustr-main.h, or just include ustr.h."
#endif

/* struct Ustr_pool is in ustr-main.h, because it's an interface */
/* Dito. ustr_pool_make_subpool, ustr_pool_clear and ustr_pool_free */

#define USTR_POOL_LL_CNTL_GET_FREE_CMP (500 + 1)
#define USTR_POOL_LL_CNTL_SET_FREE_CMP (500 + 2)
#define USTR_POOL_LL_CNTL_GET_REALLOC  (500 + 3)
#define USTR_POOL_LL_CNTL_SET_REALLOC  (500 + 4)

USTR_CONF_E_PROTO struct Ustr_pool *ustr_pool_ll_make(void)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_MALLOC();

USTR_CONF_E_PROTO
int ustr_pool_ll_cntl(struct Ustr_pool *, int, ...)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();

/*
USTR_CONF_E_PROTO struct Ustr_pool *ustr_pool_blk_make(void)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_MALLOC();
*/

/* this is the "old" name for ustr_pool_ll_make() */
USTR_CONF_E_PROTO struct Ustr_pool *ustr_pool_make_pool(void)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_DEPRECATED();

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-pool-code.h"
#endif

#endif
