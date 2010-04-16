/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_SC_H
#error " Include ustr-sc.h before this file."
#endif

USTR_CONF_i_PROTO
void ustrp__sc_free_shared(struct Ustr_pool *p, struct Ustr **ps1)
{
  USTR_ASSERT(ps1);

  if (!*ps1)
    return;
  
  USTR_ASSERT(ustr_shared(*ps1));

  ustr_setf_owner(*ps1);
  ustrp__sc_free(p, ps1);
}
USTR_CONF_I_PROTO void ustr_sc_free_shared(struct Ustr **ps1)
{ ustrp__sc_free_shared(0, ps1); }
USTR_CONF_I_PROTO
void ustrp_sc_free_shared(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  ustrp__sc_free_shared(p, &tmp);
  *ps1 = USTRP(tmp);
}

USTR_CONF_i_PROTO
struct Ustr *ustrp__sc_dupx(struct Ustr_pool *p,
                            size_t sz, size_t rbytes, int exact, int emem,
                            struct Ustr **ps1)
{
  struct Ustr *ret = ustrp__dupx(p, sz, rbytes, exact, emem, *ps1);
  struct Ustr *tmp = USTR_NULL;

  if (!ret)
    return (USTR_NULL);

  if (!ustr__dupx_cmp_eq(sz, rbytes, exact, emem, USTR__DUPX_FROM(*ps1)))
    return (ret); /* different config. so just return */

  /* swap, we only _need_ to do this when ret != *ps1 ... but it doesn't matter
   * if we always do it. */
  tmp  = *ps1;
  *ps1 = ret;
  ret  = tmp;
  
  return (ret);
}
USTR_CONF_I_PROTO
struct Ustr *ustr_sc_dupx(size_t sz, size_t rbytes, int exact, int emem,
                          struct Ustr **ps1)
{ return (ustrp__sc_dupx(0, sz, rbytes, exact, emem, ps1)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_dupx(struct Ustr_pool *p, size_t sz, size_t rbytes,
                            int exact, int emem, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  struct Ustr *ret = ustrp__sc_dupx(p, sz, rbytes, exact, emem, &tmp);
  *ps1 = USTRP(tmp);
  return (USTRP(ret));
}

USTR_CONF_i_PROTO
struct Ustr *ustrp__sc_dup(struct Ustr_pool *p, struct Ustr **ps1)
{
  struct Ustr *ret = ustrp__dup(p, *ps1);
  struct Ustr *tmp = USTR_NULL;
  
  if (!ret)
    return (USTR_NULL);

  /* swap, we only _need_ to do this when ret != *ps1 ... but it doesn't matter
   * if we always do it. */
  tmp  = *ps1;
  *ps1 = ret;
  ret  = tmp;
  
  return (ret);
}
USTR_CONF_I_PROTO struct Ustr *ustr_sc_dup(struct Ustr **ps1)
{ return (ustrp__sc_dup(0, ps1)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_dup(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  struct Ustr *ret = ustrp__sc_dup(p, &tmp);
  *ps1 = USTRP(tmp);
  return (USTRP(ret));
}

USTR_CONF_i_PROTO void ustr__reverse(char *ptr, size_t pos, size_t len)
{
  size_t clen = len;

  --pos;
  while (len > (clen / 2))
  {
    const size_t boff = pos + (clen - len);
    const size_t eoff = pos + (len  - 1);
    char tmp = ptr[boff];
    
    ptr[boff] = ptr[eoff];
    ptr[eoff] = tmp;
    
    --len;
  }
}

USTR_CONF_i_PROTO int ustrp__sc_reverse(struct Ustr_pool *p, struct Ustr **ps1)
{
  if (!ustrp__sc_ensure_owner(p, ps1))
    return (USTR_FALSE);

  ustr__reverse(ustr_wstr(*ps1), 1, ustr_len(*ps1));  

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_sc_reverse(struct Ustr **ps1)
{ return (ustrp__sc_reverse(0, ps1)); }
USTR_CONF_I_PROTO int ustrp_sc_reverse(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_reverse(p, &tmp);
  *ps1 = USTRP(tmp);
  return (ret);
}

#ifdef USTR_UTF8_H
USTR_CONF_i_PROTO
int ustrp__sc_utf8_reverse(struct Ustr_pool *p, struct Ustr **ps1)
{ /* UTF-8 reversing is like word order reversing. The simple way is to reverse
   * each "character", in place, and then reverse the entire string. */
  char *ptr;
  const unsigned char *beg;
  const unsigned char *scan;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  
  if (!(ptr = ustrp__sc_wstr(p, ps1)))
    return (USTR_FALSE);

  scan = beg = (const unsigned char *)ptr;
  while (*scan)
  {
    const unsigned char *prev = scan;
    
    USTR_ASSERT(ustr_len(*ps1) > (size_t)(scan - beg));

    scan = ustr__utf8_next(scan);
    ustr__reverse(ptr, 1 + (prev - beg), (scan - prev));
  }
  
  ustr__reverse(ptr, 1, (scan - beg));

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_sc_utf8_reverse(struct Ustr **ps1)
{ return (ustrp__sc_utf8_reverse(0, ps1)); }
USTR_CONF_I_PROTO
int ustrp_sc_utf8_reverse(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_utf8_reverse(p, &tmp);
  *ps1 = USTRP(tmp);
  return (ret);
}
#endif

USTR_CONF_i_PROTO int ustrp__sc_tolower(struct Ustr_pool *p, struct Ustr **ps1)
{
  size_t clen;
  size_t len;
  char *ptr;
  
  if (!(ptr = ustrp__sc_wstr(p, ps1)))
    return (USTR_FALSE);

  clen = len = ustr_len(*ps1);
  while (len)
  {
    if ((*ptr >= 0x41) && (*ptr <= 0x5a))
      *ptr ^= 0x20;
    ++ptr;
    --len;
  }

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_sc_tolower(struct Ustr **ps1)
{ return (ustrp__sc_tolower(0, ps1)); }
USTR_CONF_I_PROTO int ustrp_sc_tolower(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_tolower(p, &tmp);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__sc_toupper(struct Ustr_pool *p, struct Ustr **ps1)
{
  size_t clen;
  size_t len;
  char *ptr;
  
  if (!(ptr = ustrp__sc_wstr(p, ps1)))
    return (USTR_FALSE);

  clen = len = ustr_len(*ps1);
  while (len)
  {
    if ((*ptr >= 0x61) && (*ptr <= 0x7a))
      *ptr ^= 0x20;
    ++ptr;
    --len;
  }

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_sc_toupper(struct Ustr **ps1)
{ return (ustrp__sc_toupper(0, ps1)); }
USTR_CONF_I_PROTO int ustrp_sc_toupper(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_toupper(p, &tmp);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
char *ustrp__sc_export_subustr(struct Ustr_pool *p,
                               const struct Ustr *s1, size_t pos,size_t len,
                               void *(*my_alloc)(size_t))
{
  char *ret = 0;

  USTR_ASSERT(my_alloc || p);
  
  if (!ustrp__assert_valid_subustr(!!p, s1, pos, len))
  {
    errno = USTR__EINVAL;
    return (ret);
  }
  --pos;

  if (my_alloc) /* Alloc ustrp_*() to use normal export too */
    ret = (*my_alloc)(len + 1);
  else
    ret = p->pool_sys_malloc(p, len + 1);
  
  if (!ret)
  {
    errno = ENOMEM;
    return (ret);
  }
  
  memcpy(ret, ustr_cstr(s1) + pos, len);
  ret[len] = 0;

  return (ret);
}

USTR_CONF_I_PROTO
char *ustr_sc_export_subustr(const struct Ustr *s1, size_t pos, size_t len,
                             void *(*my_alloc)(size_t))
{
  USTR_ASSERT(my_alloc);
  return (ustrp__sc_export_subustr(0, s1, pos, len, my_alloc));
}
USTR_CONF_I_PROTO
char *ustrp_sc_export_subustrp(struct Ustr_pool *p,
                               const struct Ustrp *s1, size_t pos,size_t len,
                               void *(*my_alloc)(size_t))
{ return (ustrp__sc_export_subustr(p, &s1->s, pos, len, my_alloc)); }

USTR_CONF_i_PROTO
int ustrp__sc_ltrim_chrs(struct Ustr_pool *p, struct Ustr **ps1,
                         const char *chrs, size_t len)
{
  return (ustrp__del_subustr(p, ps1, 1, ustr_spn_chrs_fwd(*ps1, 0, chrs, len)));
}
USTR_CONF_I_PROTO
int ustr_sc_ltrim_chrs(struct Ustr **ps1, const char *chrs, size_t len)
{ return (ustrp__sc_ltrim_chrs(0, ps1, chrs, len)); }
USTR_CONF_I_PROTO
int ustrp_sc_ltrim_chrs(struct Ustr_pool *p, struct Ustrp **ps1,
                        const char *chrs, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_ltrim_chrs(p, &tmp, chrs, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__sc_rtrim_chrs(struct Ustr_pool *p, struct Ustr **ps1,
                         const char *chrs, size_t len)
{
  return (ustrp__del(p, ps1, ustr_spn_chrs_rev(*ps1, 0, chrs, len)));
}
USTR_CONF_I_PROTO
int ustr_sc_rtrim_chrs(struct Ustr **ps1, const char *chrs, size_t len)
{ return (ustrp__sc_rtrim_chrs(0, ps1, chrs, len)); }
USTR_CONF_I_PROTO
int ustrp_sc_rtrim_chrs(struct Ustr_pool *p, struct Ustrp **ps1,
                        const char *chrs, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_rtrim_chrs(p, &tmp, chrs, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__sc_trim_chrs(struct Ustr_pool *p, struct Ustr **ps1,
                        const char *chrs, size_t len)
{
  size_t ltrim = ustr_spn_chrs_fwd(*ps1, 0, chrs, len);
  size_t rtrim = 0;
  size_t clen = ustr_len(*ps1);
  size_t nlen = 0;
  char *ptr;

  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  
  if (ltrim == clen)
    return (ustrp__del(p, ps1, ltrim));

  rtrim = ustr_spn_chrs_rev(*ps1, 0, chrs, len);

  if (!ltrim && !rtrim)
    return (USTR_TRUE); /* minor speed hack */
  
  nlen = clen - (ltrim + rtrim);
  if (!ustr_owner(*ps1))
  {
    struct Ustr *ret = ustrp__dup_subustr(p, *ps1, 1 + ltrim, nlen);

    if (ret)
      ustrp__sc_free2(p, ps1, ret);
    
    return (!!ret);
  }
  
  ptr = ustr_wstr(*ps1);
  memmove(ptr, ptr + ltrim, nlen);

  return (ustrp__del(p, ps1, ltrim + rtrim));
}
USTR_CONF_I_PROTO
int ustr_sc_trim_chrs(struct Ustr **ps1, const char *chrs, size_t len)
{ return (ustrp__sc_trim_chrs(0, ps1, chrs, len)); }
USTR_CONF_I_PROTO
int ustrp_sc_trim_chrs(struct Ustr_pool *p, struct Ustrp **ps1,
                       const char *chrs, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_trim_chrs(p, &tmp, chrs, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
struct Ustr *ustrp__sc_vjoinx(struct Ustr_pool *p,
                              size_t sz, size_t rbytes, int exact, int emem,
                              const struct Ustr *sep,
                              const struct Ustr *s2, const struct Ustr *s3,
                              va_list ap)
{
  struct Ustr *s1 = USTR_NULL;
  const char *sptr = ustr_cstr(sep);
  size_t slen = ustr_len(sep);
  
#if USTR_CONF_HAVE_VA_COPY /* do a single allocation */
  size_t olen = 0;
  size_t len  = 0;
  struct Ustr *tmp = USTR_NULL;
  int sz_bad = USTR_FALSE;
  va_list nap;

  USTR_ASSERT(ustrp__assert_valid(0, sep));
  
  USTR__VA_COPY(nap, ap);

  len += ustr_len(s2);
  sz_bad |= (len < olen); olen = len;

  len += slen;
  sz_bad |= (len < olen); olen = len;

  len += ustr_len(s3);
  sz_bad |= (len < olen); olen = len;
  while ((tmp = va_arg(nap, struct Ustr *)))
  {
    len += slen;
    sz_bad |= (len < olen); olen = len;

    len += ustr_len(tmp);
    sz_bad |= (len < olen); olen = len;
  }
  va_end(nap);

  if (sz_bad || !(s1 = ustrp__dupx_undef(p, sz, rbytes, exact, emem, len)))
  {
    errno = USTR__ENOMEM;
    return (USTR_NULL);
  }

  len = 0;
    ustr__memcpy(s1, len, ustr_cstr(s2), ustr_len(s2)); len += ustr_len(s2);
  do
  {
    ustr__memcpy(s1, len,          sptr,         slen); len += slen;
    ustr__memcpy(s1, len, ustr_cstr(s3), ustr_len(s3)); len += ustr_len(s3);
  } while ((s3 = va_arg(ap, struct Ustr *)));
  USTR_ASSERT(olen == len);
#else
  
  USTR_ASSERT(ustrp__assert_valid(0, sep));
  
  if (!(s1 = ustrp__dupx(p, sz, rbytes, exact, USTR_FALSE, s2)))
    return (USTR_NULL);

  do {
    ustrp__add_buf(p, &s1, sptr, slen);
    ustrp__add(p, &s1, s3);
  } while ((s3 = va_arg(ap, struct Ustr *)));

  if (ustr_enomem(s1))
  {
    ustrp__sc_free(p, &s1);
    errno = USTR__ENOMEM;
    return (USTR_NULL);
  }

  if (emem)
    ustr_setf_enomem_err(s1);
#endif
  USTR_ASSERT(ustrp__assert_valid(!!p, s1));
  return (s1);
}
USTR_CONF_I_PROTO
struct Ustr *ustr_sc_vjoinx(size_t sz, size_t rbytes, int exact, int emem,
                            const struct Ustr *sep, const struct Ustr *s2,
                            const struct Ustr *s3, va_list ap)
{ return (ustrp__sc_vjoinx(0, sz, rbytes, exact, emem, sep, s2, s3, ap)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_vjoinx(struct Ustr_pool *p,
                              size_t sz, size_t rbytes, 
                              int exact, int emem,
                              const struct Ustrp *sp,const struct Ustrp *s2,
                              const struct Ustrp *s3, va_list ap)
{ return (USTRP(ustrp__sc_vjoinx(p, sz, rbytes, exact, emem,
                                 &sp->s, &s2->s, &s3->s, ap))); }
USTR_CONF_I_PROTO
struct Ustr *ustr_sc_joinx(size_t sz, size_t rbytes, 
                           int exact, int emem,
                           const struct Ustr *sep, const struct Ustr *s2,
                           const struct Ustr *s3, ...)
{
  struct Ustr *ret = USTR_NULL;
  va_list ap;
  
  va_start(ap, s3);
  ret = ustr_sc_vjoinx(sz, rbytes, exact, emem, sep, s2, s3, ap);
  va_end(ap);
  
  return (ret);
}
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_joinx(struct Ustr_pool *p,
                             size_t sz, size_t rbytes, 
                             int exact, int emem,
                             const struct Ustrp *sep,const struct Ustrp *s2,
                             const struct Ustrp *s3, ...)
{
  struct Ustrp *ret = USTRP_NULL;
  va_list ap;
  
  va_start(ap, s3);
  ret = ustrp_sc_vjoinx(p, sz, rbytes, exact, emem, sep, s2, s3, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO
struct Ustr *ustr_sc_vjoin(const struct Ustr *sep, const struct Ustr *s2,
                               const struct Ustr *s3, va_list ap)
{ return (ustrp__sc_vjoinx(0, USTR__DUPX_DEF, sep, s2, s3, ap)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_vjoin(struct Ustr_pool *p, const struct Ustrp *sep,
                                 const struct Ustrp *s2,const struct Ustrp *s3, 
                                 va_list ap)
{ return (USTRP(ustrp__sc_vjoinx(p,USTR__DUPX_DEF,&sep->s,&s2->s,&s3->s,ap))); }
USTR_CONF_I_PROTO
struct Ustr *ustr_sc_join(const struct Ustr *sep, const struct Ustr *s2,
                          const struct Ustr *s3, ...)
{
  struct Ustr *ret = USTR_NULL;
  va_list ap;
  
  va_start(ap, s3);
  ret = ustr_sc_vjoin(sep, s2, s3, ap);
  va_end(ap);
  
  return (ret);
}
USTR_CONF_I_PROTO
struct Ustrp *
ustrp_sc_join(struct Ustr_pool *p, const struct Ustrp *sep,
              const struct Ustrp *s2, const struct Ustrp *s3, ...)
{
  struct Ustrp *ret = USTRP_NULL;
  va_list ap;
  
  va_start(ap, s3);
  ret = ustrp_sc_vjoin(p, sep, s2, s3, ap);
  va_end(ap);
  
  return (ret);
}

/* ---- concat ---- */

USTR_CONF_i_PROTO
struct Ustr *ustrp__sc_vconcatx(struct Ustr_pool *p,
                                size_t sz, size_t rbytes, int exact, int emem,
                                const struct Ustr *s2, va_list ap)
{ return (ustrp__sc_vjoinx(p, sz,rbytes,exact,emem, USTR(""),USTR(""),s2,ap)); }
USTR_CONF_I_PROTO
struct Ustr *ustr_sc_vconcatx(size_t sz, size_t rbytes, int exact, int emem,
                              const struct Ustr *s2, va_list ap)
{ return (ustrp__sc_vconcatx(0, sz, rbytes, exact, emem, s2, ap)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_vconcatx(struct Ustr_pool *p,
                                size_t sz, size_t rbytes, int exact, int emem,
                                const struct Ustrp *s2, va_list ap)
{ return (USTRP(ustrp__sc_vconcatx(p, sz,rbytes,exact,emem, &s2->s, ap))); }
USTR_CONF_I_PROTO
struct Ustr *ustr_sc_concatx(size_t sz, size_t rbytes, int exact, int emem,
                             const struct Ustr *s2, ...)
{
  struct Ustr *ret = USTR_NULL;
  va_list ap;
  
  va_start(ap, s2);
  ret = ustr_sc_vconcatx(sz, rbytes, exact, emem, s2, ap);
  va_end(ap);
  
  return (ret);
}
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_concatx(struct Ustr_pool *p,
                               size_t sz, size_t rbytes, int exact, int emem,
                               const struct Ustrp *s2, ...)
{
  struct Ustrp *ret = USTRP_NULL;
  va_list ap;
  
  va_start(ap, s2);
  ret = ustrp_sc_vconcatx(p, sz, rbytes, exact, emem, s2, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO
struct Ustr *ustr_sc_vconcat(const struct Ustr *s2, va_list ap)
{ return (ustrp__sc_vconcatx(0, USTR__DUPX_DEF, s2, ap)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_vconcat(struct Ustr_pool *p,
                               const struct Ustrp *s2, va_list ap)
{ return (USTRP(ustrp__sc_vconcatx(p, USTR__DUPX_DEF, &s2->s, ap))); }
USTR_CONF_I_PROTO
struct Ustr *ustr_sc_concat(const struct Ustr *s2, ...)
{
  struct Ustr *ret = USTR_NULL;
  va_list ap;
  
  va_start(ap, s2);
  ret = ustr_sc_vconcat(s2, ap);
  va_end(ap);
  
  return (ret);
}
USTR_CONF_I_PROTO
struct Ustrp *ustrp_sc_concat(struct Ustr_pool *p,
                              const struct Ustrp *s2, ...)
{
  struct Ustrp *ret = USTRP_NULL;
  va_list ap;
  
  va_start(ap, s2);
  ret = ustrp_sc_vconcat(p, s2, ap);
  va_end(ap);
  
  return (ret);
}

