/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_PARSE_H
#define USTR_PARSE_H 1

#ifndef USTR_MAIN_H
#error " You should have already included ustr-main.h, or just include ustr.h."
#endif

#define USTR_TYPE_PARSE_NUM_ERR_NONE 0
#define USTR_TYPE_PARSE_NUM_ERR_ONLY_S 1
#define USTR_TYPE_PARSE_NUM_ERR_ONLY_SPM 2
#define USTR_TYPE_PARSE_NUM_ERR_ONLY_SPMX 3
#define USTR_TYPE_PARSE_NUM_ERR_OOB 4
#define USTR_TYPE_PARSE_NUM_ERR_OVERFLOW 5
#define USTR_TYPE_PARSE_NUM_ERR_NEGATIVE 6
#define USTR_TYPE_PARSE_NUM_ERR_BEG_ZERO 7

#define USTR_FLAG_PARSE_NUM_DEF          0U
#define USTR__MASK_PARSE_NUM_BASE (63) /* (1<<6) - 1 */
/* #define USTR_FLAG_PARSE_NUM_LOCAL       (1U<<6) */
#define USTR_FLAG_PARSE_NUM_SEP         (1U<<7)
#define USTR_FLAG_PARSE_NUM_OVERFLOW    (1U<<8)
#define USTR_FLAG_PARSE_NUM_SPACE       (1U<<9)
#define USTR_FLAG_PARSE_NUM_NO_BEG_ZERO (1U<<10)
#define USTR_FLAG_PARSE_NUM_NO_BEG_PM   (1U<<11)
#define USTR_FLAG_PARSE_NUM_NO_NEGATIVE (1U<<12)
#define USTR_FLAG_PARSE_NUM_EXACT       (1U<<13)


#if USTR_CONF_HAVE_STDINT_H
USTR_CONF_E_PROTO
uintmax_t ustr_parse_uintmaxx(const struct Ustr *, size_t, unsigned int,
                              uintmax_t, uintmax_t, const char *,
                              size_t *,unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 6));

USTR_CONF_E_PROTO
uintmax_t ustr_parse_uintmax(const struct Ustr *, size_t, unsigned int, size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_E_PROTO
intmax_t ustr_parse_intmax(const struct Ustr *, size_t, unsigned int, size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
#endif

USTR_CONF_E_PROTO
unsigned long ustr_parse_ulongx(const struct Ustr *, size_t, unsigned int,
                                unsigned long, unsigned long,
                                const char *, size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 6));

USTR_CONF_E_PROTO
unsigned long ustr_parse_ulong(const struct Ustr *, size_t, unsigned int,
                               size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_E_PROTO
long ustr_parse_long(const struct Ustr *, size_t, unsigned int,
                     size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_E_PROTO
unsigned int ustr_parse_uint(const struct Ustr *, size_t, unsigned int,
                             size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_E_PROTO
int ustr_parse_int(const struct Ustr *, size_t, unsigned int,
                   size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_E_PROTO
unsigned short ustr_parse_ushort(const struct Ustr *, size_t, unsigned int,
                                 size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_E_PROTO
short ustr_parse_short(const struct Ustr *, size_t, unsigned int,
                       size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-parse-code.h"
#endif


/* ---------------- pool wrapper APIs ---------------- */

#if USTR_CONF_HAVE_STDINT_H
USTR_CONF_EI_PROTO
uintmax_t ustrp_parse_uintmaxx(const struct Ustrp *, size_t, unsigned int,
                               uintmax_t, uintmax_t, const char *,
                               size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 6));
USTR_CONF_EI_PROTO
uintmax_t ustrp_parse_uintmax(const struct Ustrp *, size_t, unsigned int,
                              size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_EI_PROTO
intmax_t ustrp_parse_intmax(const struct Ustrp *, size_t, unsigned int,
                            size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

#endif

USTR_CONF_EI_PROTO
unsigned long ustrp_parse_ulongx(const struct Ustrp *, size_t, unsigned int,
                                 unsigned long, unsigned long,
                                 const char *, size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 6));

USTR_CONF_EI_PROTO
unsigned long ustrp_parse_ulong(const struct Ustrp *, size_t, unsigned int,
                                size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_EI_PROTO
long ustrp_parse_long(const struct Ustrp *, size_t, unsigned int,
                      size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_EI_PROTO
unsigned int ustrp_parse_uint(const struct Ustrp *, size_t, unsigned int,
                              size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_EI_PROTO
int ustrp_parse_int(const struct Ustrp *, size_t, unsigned int,
                    size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_EI_PROTO
unsigned short ustrp_parse_ushort(const struct Ustrp *, size_t, unsigned int,
                                  size_t *, unsigned *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_EI_PROTO
short ustrp_parse_short(const struct Ustrp *, size_t, unsigned int,
                        size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

#if USTR_CONF_COMPILE_USE_INLINE
# if USTR_CONF_HAVE_STDINT_H
USTR_CONF_II_PROTO
uintmax_t ustrp_parse_uintmaxx(const struct Ustrp *s1, size_t off,
                               unsigned int flags,
                               uintmax_t nmin, uintmax_t nmax,
                               const char *sep, size_t *len, unsigned int *ern)
{ return (ustr_parse_uintmaxx(&s1->s, off, flags, nmin, nmax, sep, len, ern)); }

USTR_CONF_II_PROTO
uintmax_t ustrp_parse_uintmax(const struct Ustrp *s1, size_t off,
                              unsigned int flags,
                              size_t *len, unsigned int *ern)
{ return (ustr_parse_uintmax(&s1->s, off, flags, len, ern)); }

USTR_CONF_II_PROTO
intmax_t ustrp_parse_intmax(const struct Ustrp *s1, size_t off, 
                            unsigned int flags, size_t *len, unsigned int *ern)
{ return (ustr_parse_intmax(&s1->s, off, flags, len, ern)); }
# endif

USTR_CONF_II_PROTO
unsigned long ustrp_parse_ulongx(const struct Ustrp *s1, size_t off,
                                 unsigned int flags,
                                 unsigned long nmin, unsigned long nmax,
                                 const char *sep, size_t *len, unsigned *ern)
{ return (ustr_parse_ulongx(&s1->s, off, flags, nmin, nmax, sep, len, ern)); }

USTR_CONF_II_PROTO
unsigned long ustrp_parse_ulong(const struct Ustrp *s1, size_t off, 
                                unsigned int flags,
                                size_t *len, unsigned int *ern)
{ return (ustr_parse_ulong(&s1->s, off, flags, len, ern)); }
USTR_CONF_II_PROTO
long ustrp_parse_long(const struct Ustrp *s1, size_t off, 
                      unsigned int flags, size_t *len, unsigned int *ern)
{ return (ustr_parse_long(&s1->s, off, flags, len, ern)); }

USTR_CONF_II_PROTO
unsigned int ustrp_parse_uint(const struct Ustrp *s1, size_t off, 
                              unsigned int flags,
                              size_t *len, unsigned int *ern)
{ return (ustr_parse_uint(&s1->s, off, flags, len, ern)); }
USTR_CONF_II_PROTO
int ustrp_parse_int(const struct Ustrp *s1, size_t off, 
                    unsigned int flags, size_t *len, unsigned int *ern)
{ return (ustr_parse_int(&s1->s, off, flags, len, ern)); }

USTR_CONF_II_PROTO
unsigned short ustrp_parse_ushort(const struct Ustrp *s1, size_t off, 
                                  unsigned int flags,
                                  size_t *len, unsigned int *ern)
{ return (ustr_parse_ushort(&s1->s, off, flags, len, ern)); }
USTR_CONF_II_PROTO
short ustrp_parse_short(const struct Ustrp *s1, size_t off, 
                        unsigned int flags, size_t *len, unsigned int *ern)
{ return (ustr_parse_short(&s1->s, off, flags, len, ern)); }
#endif

#endif

