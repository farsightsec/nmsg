/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_CNTL_H
#define USTR_CNTL_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

#define USTR_CNTL_OPT_GET_REF_BYTES   ( 1)
#define USTR_CNTL_OPT_SET_REF_BYTES   ( 2)
#define USTR_CNTL_OPT_GET_HAS_SIZE    ( 3)
#define USTR_CNTL_OPT_SET_HAS_SIZE    ( 4)
#define USTR_CNTL_OPT_GET_EXACT_BYTES ( 5)
#define USTR_CNTL_OPT_SET_EXACT_BYTES ( 6)
#define USTR_CNTL_OPT_GET_MEM         ( 7)
#define USTR_CNTL_OPT_SET_MEM         ( 8)
#define USTR_CNTL_OPT_GET_MC_M_SCRUB  ( 9)
#define USTR_CNTL_OPT_SET_MC_M_SCRUB  (10)
#define USTR_CNTL_OPT_GET_MC_F_SCRUB  (11)
#define USTR_CNTL_OPT_SET_MC_F_SCRUB  (12)
#define USTR_CNTL_OPT_GET_MC_R_SCRUB  (13)
#define USTR_CNTL_OPT_SET_MC_R_SCRUB  (14)
#define USTR_CNTL_OPT_GET_FMT         (15)
#define USTR_CNTL_OPT_SET_FMT         (16)

/* move to dynamic configuration, so it's more usable from a shared library */
#undef  USTR_CONF_REF_BYTES
#define USTR_CONF_REF_BYTES (ustr__opts->ref_bytes)
#undef  USTR_CONF_HAS_SIZE
#define USTR_CONF_HAS_SIZE (ustr__opts->has_size)
#undef  USTR_CONF_EXACT_BYTES
#define USTR_CONF_EXACT_BYTES (ustr__opts->exact_bytes)
#undef  USTR_CONF_MALLOC
#define USTR_CONF_MALLOC(x)     ((*ustr__opts->umem.sys_malloc)(x))
#undef  USTR_CONF_REALLOC
#define USTR_CONF_REALLOC(x, y) ((*ustr__opts->umem.sys_realloc)((x), (y)))
#undef  USTR_CONF_FREE
#define USTR_CONF_FREE(x)       ((*ustr__opts->umem.sys_free)(x))
#undef  USTR_CONF_VSNPRINTF_BEG
#define USTR_CONF_VSNPRINTF_BEG    ustr__opts->ufmt.sys_vsnprintf_beg
#undef  USTR_CONF_VSNPRINTF_END
#define USTR_CONF_VSNPRINTF_END    ustr__opts->ufmt.sys_vsnprintf_end

struct Ustr_cntl_mem
{
 void *(*sys_malloc)(size_t);
 void *(*sys_realloc)(void *, size_t);
 void  (*sys_free)(void *);
};

struct Ustr_cntl_fmt
{
 int (*sys_vsnprintf_beg)(char *, size_t, const char *, va_list);
 int (*sys_vsnprintf_end)(char *, size_t, const char *, va_list); 
};

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
struct Ustr_opts
{
 size_t ref_bytes;

 struct Ustr_cntl_mem umem;
 struct Ustr_cntl_fmt ufmt;

 unsigned int has_size    : 1;
 unsigned int exact_bytes : 1;
 unsigned int mc_m_scrub  : 1;
 unsigned int mc_f_scrub  : 1;
 unsigned int mc_r_scrub  : 1;
};

/* this is for use within the shared library only... */
extern struct Ustr_opts ustr__opts[1];

USTR_CONF_e_PROTO int   ustr__cntl_mc_setup_env2bool(const char *, int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_e_PROTO void  ustr__cntl_mc_setup_main(void);
USTR_CONF_e_PROTO void *ustr__cntl_mc_setup_malloc(size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_e_PROTO void *ustr__cntl_mc_malloc(size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_e_PROTO void *ustr__cntl_mc_realloc(void *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_e_PROTO void  ustr__cntl_mc_free(void *);
#else
struct Ustr_opts; /* declare opaque struct */
#endif

#if USTR_CONF_COMPILE_TYPEDEF
typedef struct Ustr_cntl_mem  Ustr_cntl_mem;
typedef struct Ustr_cntl_fmt  Ustr_cntl_fmt;
typedef struct Ustr_opts      Ustr_opts;
#endif

USTR_CONF_E_PROTO int ustr_cntl_opt(int, ...)
    USTR__COMPILE_ATTR_NONNULL_A();

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
#include "ustr-cntl-code.h"
#endif

#endif
