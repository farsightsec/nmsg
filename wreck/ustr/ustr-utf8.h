/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_UTF8_H
#define USTR_UTF8_H 1

#ifndef USTR_MAIN_H
#error " You should have already included ustr-main.h, or just include ustr.h."
#endif

#ifdef __unix__ /* FIXME: Hacky, but this isn't a 9899:1999 type */
#define USTR__SSIZE ssize_t
#else
#define USTR__SSIZE long
#endif


USTR_CONF_E_PROTO
int ustr_utf8_valid(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_utf8_len(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
USTR__SSIZE ustr_utf8_width(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_utf8_chars2bytes(const struct Ustr *, size_t, size_t, size_t *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_E_PROTO
size_t ustr_utf8_bytes2chars(const struct Ustr *, size_t, size_t, size_t *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_E_PROTO
int ustrp_utf8_valid(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_len(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
USTR__SSIZE ustrp_utf8_width(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_chars2bytes(const struct Ustrp *, size_t, size_t, size_t *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_EI_PROTO
size_t ustrp_utf8_bytes2chars(const struct Ustrp *, size_t, size_t, size_t *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-utf8-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-utf8-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
int ustrp_utf8_valid(const struct Ustrp *s1)
{ return (ustr_utf8_valid(&s1->s)); }
USTR_CONF_II_PROTO
size_t ustrp_utf8_len(const struct Ustrp *s1)
{ return (ustr_utf8_len(&s1->s)); }
USTR_CONF_II_PROTO
USTR__SSIZE ustrp_utf8_width(const struct Ustrp *s1)
{ return (ustr_utf8_width(&s1->s)); }
USTR_CONF_II_PROTO
size_t ustrp_utf8_chars2bytes(const struct Ustrp *s1, size_t pos, size_t len,
                              size_t *ret_pos)
{ return (ustr_utf8_chars2bytes(&s1->s, pos, len, ret_pos)); }
USTR_CONF_II_PROTO
size_t ustrp_utf8_bytes2chars(const struct Ustrp *s1, size_t pos, size_t len,
                              size_t *ret_pos)
{ return (ustr_utf8_bytes2chars(&s1->s, pos, len, ret_pos)); }
#endif

#endif
