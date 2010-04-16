/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_CMP_INTERNAL_H
#define USTR_CMP_INTERNAL_H 1

#ifndef USTR_MAIN_H
# error " You should have already included ustr-main.h, or just include ustr.h"
#endif

USTR_CONF_e_PROTO int ustr__memcasecmp(const void *, const void *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

#endif
