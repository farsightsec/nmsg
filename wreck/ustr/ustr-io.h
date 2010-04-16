/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_IO_H
#define USTR_IO_H 1

#ifndef USTR_MAIN_H
#error " You should have already included ustr-main.h, or just include ustr.h."
#endif

USTR_CONF_E_PROTO int ustr_io_get(struct Ustr **, FILE *, size_t, size_t *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 2));
USTR_CONF_E_PROTO int ustr_io_getfile(struct Ustr **, FILE *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_io_getfilename(struct Ustr **, const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO int ustr_io_getdelim(struct Ustr **, FILE *, char)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_io_getline(struct Ustr **, FILE *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO int ustr_io_put(struct Ustr **, FILE *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_io_putline(struct Ustr **, FILE *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_io_putfile(struct Ustr **, FILE *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_io_putfileline(struct Ustr **, FILE *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
int ustr_io_putfilename(struct Ustr **, const char *, const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
int ustrp_io_get(struct Ustr_pool *, struct Ustrp **, FILE *, size_t, size_t *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_io_getfile(struct Ustr_pool *, struct Ustrp **, FILE *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_io_getfilename(struct Ustr_pool *, struct Ustrp **,const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));

USTR_CONF_E_PROTO
int ustrp_io_getdelim(struct Ustr_pool *, struct Ustrp **, FILE *, char)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO int ustrp_io_getline(struct Ustr_pool *, struct Ustrp**,FILE*)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));

USTR_CONF_E_PROTO
int ustrp_io_put(struct Ustr_pool *, struct Ustrp **, FILE *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_io_putline(struct Ustr_pool *, struct Ustrp **, FILE *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_EI_PROTO
int ustrp_io_putfile(struct Ustr_pool *, struct Ustrp **, FILE *)
   USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_EI_PROTO
int ustrp_io_putfileline(struct Ustr_pool *, struct Ustrp **, FILE *)
   USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_io_putfilename(struct Ustr_pool *, struct Ustrp **,
                         const char *, const char *)
   USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3, 4));

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-io-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-io-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO int ustr_io_putfile(struct Ustr **ps1, FILE *fp)
{ return (ustr_io_put(ps1, fp, ustr_len(*ps1))); }
USTR_CONF_II_PROTO int ustr_io_putfileline(struct Ustr **ps1, FILE *fp)
{ return (ustr_io_putline(ps1, fp, ustr_len(*ps1))); }

USTR_CONF_II_PROTO
int ustrp_io_putfile(struct Ustr_pool *p, struct Ustrp **ps1, FILE *fp)
{ return (ustrp_io_put(p, ps1, fp, ustrp_len(*ps1))); }
USTR_CONF_II_PROTO
int ustrp_io_putfileline(struct Ustr_pool *p, struct Ustrp **ps1, FILE *fp)
{ return (ustrp_io_putline(p, ps1, fp, ustrp_len(*ps1))); }
#endif

#endif
