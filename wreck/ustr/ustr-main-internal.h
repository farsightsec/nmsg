/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_MAIN_INTERNAL_H
#define USTR_MAIN_INTERNAL_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

#include <errno.h>  /* EDOM, EILSEQ, ERANGE, hopefully ENOMEM, etc. */

#ifdef ENOMEM
# define USTR__ENOMEM ENOMEM
#else
# define USTR__ENOMEM EDOM   /* ENOMEM isn't in ISO 9899:1999, *sigh* */
#endif
#ifdef EINVAL
# define USTR__EINVAL EINVAL
#else
# define USTR__EINVAL ERANGE /* EINVAL isn't in ISO 9899:1999, *sigh* */
#endif

/* default sized is 1 byte... */
#define USTR__DUPX_DEF                                  \
    USTR_CONF_HAS_SIZE, USTR_CONF_REF_BYTES,            \
    USTR_CONF_EXACT_BYTES, USTR_FALSE
#define USTR__DUPX_FROM(x)                                              \
    (ustr_alloc(x) ?                                                    \
     (ustr_sized(x) ? ustr__sz_get(x) : 0) : USTR_CONF_HAS_SIZE),       \
    (ustr_alloc(x) ? USTR__REF_LEN(x) : USTR_CONF_REF_BYTES),           \
    (ustr_alloc(x) ? ustr_exact(x) : USTR_CONF_EXACT_BYTES), ustr_enomem(x)


#define USTR__ASSERT_MALLOC_CHECK_MEM(p, s1) ((p) ||                    \
    USTR_CNTL_MALLOC_CHECK_MEM_USTR(s1))

USTR_CONF_e_PROTO int ustr__dupx_cmp_eq(size_t, size_t, int, int,
                                        size_t, size_t, int, int)
    USTR__COMPILE_ATTR_CONST() USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_e_PROTO size_t ustr__sz_get(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO size_t ustr__nb(size_t num)
    USTR__COMPILE_ATTR_CONST() USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_e_PROTO
int ustrp__assert_valid(int, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
size_t ustrp__assert_valid_subustr(int, const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((2));

USTR_CONF_e_PROTO void ustr__embed_val_set(unsigned char *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO int ustr__ref_set(struct Ustr *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO void ustr__len_set(struct Ustr *s1, size_t len)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO void ustr__sz_set(struct Ustr *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO int ustr__ref_add(struct Ustr *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO size_t ustr__ref_del(struct Ustr *s1)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO void ustrp__free(struct Ustr_pool *, struct Ustr *);
USTR_CONF_e_PROTO
void ustrp__sc_free2(struct Ustr_pool *p, struct Ustr **ps1, struct Ustr *s2)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO size_t ustr__ns(size_t num)
    USTR__COMPILE_ATTR_CONST() USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_e_PROTO void ustr__terminate(unsigned char *, int, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_e_PROTO
struct Ustr *ustrp__dupx_undef(struct Ustr_pool *, size_t, size_t, int, int,
                               size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_e_PROTO
int ustrp__rw_realloc(struct Ustr_pool *, struct Ustr **, int, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO void ustr__memcpy(struct Ustr *, size_t, const void *,size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO void ustr__memset(struct Ustr *, size_t, int, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO int ustrp__realloc(struct Ustr_pool *, struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO int ustr__rw_mod(struct Ustr *, size_t, size_t *, size_t *,
                                   size_t *, size_t *, int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO int ustrp__del(struct Ustr_pool *, struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
int ustrp__del_subustr(struct Ustr_pool *, struct Ustr **, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
struct Ustr *ustrp__dupx_empty(struct Ustr_pool *, size_t, size_t, int, int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_e_PROTO
struct Ustr *ustrp__dupx_buf(struct Ustr_pool *, size_t, size_t, int, int,
                             const void *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((6));
USTR_CONF_e_PROTO
struct Ustr *ustrp__dup(struct Ustr_pool *, const struct Ustr *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
struct Ustr *ustrp__dupx(struct Ustr_pool *, size_t, size_t, int ,
                         int, const struct Ustr *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((6));
USTR_CONF_e_PROTO
struct Ustr *ustrp__dupx_subustr(struct Ustr_pool *,
                                 size_t, size_t, int, int,
                                 const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((6));
USTR_CONF_e_PROTO
struct Ustr *ustrp__dup_subustr(struct Ustr_pool *,
                                const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
struct Ustr *ustrp__dupx_rep_chr(struct Ustr_pool *, size_t, size_t, int, int,
                                 char, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_e_PROTO
int ustrp__add_undef(struct Ustr_pool *, struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
int ustrp__add_buf(struct Ustr_pool *, struct Ustr **, const void *, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO int ustr__treat_as_buf(const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO
int ustrp__add(struct Ustr_pool *, struct Ustr **, const struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO
int ustrp__add_subustr(struct Ustr_pool *, struct Ustr **,
                       const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO
int ustrp__add_rep_chr(struct Ustr_pool *p, struct Ustr **, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

USTR_CONF_e_PROTO void ustrp__sc_del(struct Ustr_pool *, struct Ustr **)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO void ustrp__sc_free(struct Ustr_pool *, struct Ustr **)
    USTR__COMPILE_ATTR_NONNULL_L((2));

USTR_CONF_e_PROTO int ustrp__sc_ensure_owner(struct Ustr_pool *, struct Ustr **)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO char *ustrp__sc_wstr(struct Ustr_pool *, struct Ustr **)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));

#endif
