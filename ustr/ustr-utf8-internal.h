/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_UTF8_INTERNAL_H
#define USTR_UTF8_INTERNAL_H 1

#ifndef USTR_MAIN_H
# error " You should have already included ustr-main.h, or just include ustr.h"
#endif

struct ustr__utf8_interval
{
 unsigned int first;
 unsigned int last;
};

#if ! USTR_CONF_HAVE_STDINT_H
# define USTR__UTF8_WCHAR unsigned long
#else
# define USTR__UTF8_WCHAR uint_least32_t
#endif

USTR_CONF_e_PROTO
int ustr__utf8_bisearch(USTR__UTF8_WCHAR,const struct ustr__utf8_interval*,int);
USTR_CONF_e_PROTO
USTR__SSIZE ustr__utf8_mk_wcwidth(USTR__UTF8_WCHAR)
   USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_e_PROTO
USTR__UTF8_WCHAR ustr__utf8_check(const unsigned char **)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_e_PROTO
const unsigned char *ustr__utf8_prev(const unsigned char *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO
const unsigned char *ustr__utf8_next(const unsigned char *)
    USTR__COMPILE_ATTR_NONNULL_A();

#endif
