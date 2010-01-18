/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_FMT_INTERNAL_H
#define USTR_FMT_INTERNAL_H 1

#ifndef USTR_MAIN_H
# error " You should have already included ustr-main.h, or just include ustr.h"
#endif

/* snprintf is "expensive", so calling it once with a stack buffer followed by
 * a memcpy() is almost certainly better than calling it twice */
#define USTR__SNPRINTF_LOCAL        128

/*  Retarded versions of snprintf() return -1 (Ie. Solaris) instead of the
 * desired length so we have to loop calling vsnprintf() until we find a
 * value "big enough".
 *  However ISO 9899:1999 says vsnprintf returns -1 for bad multi-byte strings,
 * so we don't want to loop forever.
 *  So we try and work out USTR_CONF_HAVE_RETARDED_VSNPRINTF, but if it's on
 * when it doesn't need to be it'll be horribly slow on multi-byte errors. */
#define USTR__RETARDED_SNPRINTF_MIN (USTR__SNPRINTF_LOCAL * 2)
#define USTR__RETARDED_SNPRINTF_MAX (1024 * 1024 * 256)

#ifndef USTR_CONF_HAVE_RETARDED_VSNPRINTF /* safeish, but see above */
#define USTR_CONF_HAVE_RETARDED_VSNPRINTF 1
#endif

#if USTR_CONF_HAVE_VA_COPY
# if USTR_CONF_HAVE_RETARDED_VSNPRINTF
USTR_CONF_e_PROTO
int ustr__retard_vfmt_ret(const char *fmt, va_list ap)
    USTR__COMPILE_ATTR_NONNULL_A() USTR__COMPILE_ATTR_FMT(1, 0);
# else
#  define ustr__retard_vfmt_ret(x, y) (-1)
# endif

USTR_CONF_e_PROTO
int ustrp__add_vfmt_lim(struct Ustr_pool *p, struct Ustr **ps1, size_t lim,
                        const char *fmt, va_list ap)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 0);
USTR_CONF_e_PROTO
struct Ustr *ustrp__dupx_vfmt_lim(struct Ustr_pool *,
                                  size_t, size_t, int, int, size_t,
                                  const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((7)) USTR__COMPILE_ATTR_FMT(7, 0);
#endif

#endif
