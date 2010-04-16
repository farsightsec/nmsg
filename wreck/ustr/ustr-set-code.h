/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_SET_H
#error " You should have already included ustr-set.h, or just include ustr.h."
#endif

USTR_CONF_i_PROTO
int ustrp__set_undef(struct Ustr_pool *p, struct Ustr **ps1, size_t nlen)
{
  struct Ustr *s1  = USTR_NULL;
  struct Ustr *ret = USTR_NULL;
  size_t clen = 0;
  size_t sz  = 0;
  size_t oh  = 0;
  size_t osz = 0;
  size_t nsz = 0;
  int alloc = USTR_FALSE;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  s1 = *ps1;
  clen = ustr_len(s1);
  if (nlen == clen)
  {
    if (ustr_owner(s1))
      return (USTR_TRUE);
  }
  else if (ustr__rw_mod(s1, nlen, &sz, &oh, &osz, &nsz, &alloc))
  {
    if (nlen > clen)
      return (ustrp__add_undef(p, ps1, (nlen - clen)));
    else
      return (ustrp__del(p, ps1, (clen - nlen)));
  }
  else if (ustr_limited(s1))
    goto fail_enomem;
  
  if (!(ret = ustrp__dupx_undef(p, USTR__DUPX_FROM(s1), nlen)))
    goto fail_enomem;
  
  ustrp__sc_free2(p, ps1, ret);
  return (USTR_TRUE);

 fail_enomem:
  ustr_setf_enomem_err(s1);
  return (USTR_FALSE);
}
USTR_CONF_I_PROTO int ustr_set_undef(struct Ustr **ps1, size_t nlen)
{ return (ustrp__set_undef(0, ps1, nlen)); }
USTR_CONF_I_PROTO
int ustrp_set_undef(struct Ustr_pool *p, struct Ustrp **ps1, size_t nlen)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__set_undef(p, &tmp, nlen);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__set_empty(struct Ustr_pool *p, struct Ustr **ps1)
{
  struct Ustr *ret = USTR_NULL;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  if (ustr_sized(*ps1) && ustr_owner(*ps1))
    return (ustrp__del(p, ps1, ustr_len(*ps1)));
  
  if (!(ret = ustrp__dupx_empty(p, USTR__DUPX_FROM(*ps1))))
  {
    ustr_setf_enomem_err(*ps1);
    return (USTR_FALSE);
  }
  
  ustrp__sc_free2(p, ps1, ret);
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_set_empty(struct Ustr **ps1)
{ return (ustrp__set_empty(0, ps1)); }
USTR_CONF_I_PROTO int ustrp_set_empty(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__set_empty(p, &tmp);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__set_buf(struct Ustr_pool *p, struct Ustr **ps1,
                                     const void *buf, size_t len)
{
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  if (!ustrp__set_undef(p, ps1, len))
    return (USTR_FALSE);
  
  ustr__memcpy(*ps1, 0, buf, len);

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO
int ustr_set_buf(struct Ustr **ps1, const void *buf, size_t len)
{ return (ustrp__set_buf(0, ps1, buf, len)); }
USTR_CONF_I_PROTO int ustrp_set_buf(struct Ustr_pool *p, struct Ustrp **ps1,
                                    const void *buf, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__set_buf(p, &tmp, buf, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__set(struct Ustr_pool *p, struct Ustr **ps1, const struct Ustr *s2)
{
  struct Ustr *ret = USTR_NULL;
  
  USTR_ASSERT(ps1 &&
              ustrp__assert_valid(!!p, *ps1) && ustrp__assert_valid(!!p, s2));

  if (*ps1 == s2)
    return (USTR_TRUE);

  if (ustr__treat_as_buf(*ps1, 0, ustr_len(s2)))
    return (ustrp__set_buf(p, ps1, ustr_cstr(s2), ustr_len(s2)));

  if (!(ret = ustrp__dupx(p, USTR__DUPX_FROM(*ps1), s2)))
  {
    ustr_setf_enomem_err(*ps1);
    return (USTR_FALSE);
  }
  
  ustrp__sc_free2(p, ps1, ret);
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_set(struct Ustr **ps1, const struct Ustr *s2)
{ return (ustrp__set(0, ps1, s2)); }
USTR_CONF_I_PROTO
int ustrp_set(struct Ustr_pool *p, struct Ustrp **ps1, const struct Ustrp *s2)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__set(p, &tmp, &s2->s);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__set_subustr(struct Ustr_pool *p, struct Ustr **ps1,
                       const struct Ustr *s2, size_t pos, size_t len)
{
  size_t clen = 0;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  if (!len)
    return (ustrp__del(p, ps1, ustr_len(*ps1)));
  
  clen = ustrp__assert_valid_subustr(!!p, s2, pos, len);
  if (!clen)
    return (USTR_FALSE);
  if (len == clen)
    return (ustrp__set(p, ps1, s2));
  
  if ((*ps1 == s2) && ustr_owner(s2) && ustr_alloc(s2))
  { /* only one reference, so we can't take _cstr() before we realloc */
    --pos;
    ustrp__del(p, ps1, clen - (pos + len)); /* delete bit after */
    ustrp__del_subustr(p, ps1, 1, pos);     /* delete bit before */
    return (USTR_TRUE);
  }
  
  return (ustrp__set_buf(p, ps1, ustr_cstr(s2) + pos - 1, len));
}
USTR_CONF_I_PROTO int ustr_set_subustr(struct Ustr **ps1, const struct Ustr *s2,
                                       size_t pos, size_t len)
{ return (ustrp__set_subustr(0, ps1, s2, pos, len)); }
USTR_CONF_I_PROTO
int ustrp_set_subustrp(struct Ustr_pool *p, struct Ustrp **ps1,
                       const struct Ustrp *s2, size_t pos, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__set_subustr(p, &tmp, &s2->s, pos, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__set_rep_chr(struct Ustr_pool *p, struct Ustr **ps1,
                                         char chr, size_t len)
{
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  if (!ustrp__set_undef(p, ps1, len))
    return (USTR_FALSE);

  ustr__memset(*ps1, 0, chr, len);

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO
int ustr_set_rep_chr(struct Ustr **ps1, char chr, size_t len)
{ return (ustrp__set_rep_chr(0, ps1, chr, len)); }
USTR_CONF_I_PROTO int ustrp_set_rep_chr(struct Ustr_pool *p, struct Ustrp **ps1,
                                        char chr, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__set_rep_chr(p, &tmp, chr, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

#ifdef USTR_FMT_H
# if USTR_CONF_HAVE_VA_COPY
USTR_CONF_i_PROTO
int ustrp__set_vfmt_lim(struct Ustr_pool *p, struct Ustr **ps1, size_t lim,
                        const char *fmt, va_list ap)
{ /* NOTE: Copy and pasted so we can use ustrp_set_undef() */
  va_list nap;
  int rc = -1;
  char buf[USTR__SNPRINTF_LOCAL];
  
  USTR__VA_COPY(nap, ap);
  rc = USTR_CONF_VSNPRINTF_BEG(buf, sizeof(buf), fmt, nap);
  va_end(nap);

  if ((rc == -1) && ((rc = ustr__retard_vfmt_ret(fmt, ap)) == -1))
    return (USTR_FALSE);

  if (lim && ((size_t)rc > lim))
    rc = lim;
  
  if ((size_t)rc < sizeof(buf)) /* everything is done */
    return (ustrp__set_buf(p, ps1, buf, rc));
  
  if (!ustrp__set_undef(p, ps1, rc))
    return (USTR_FALSE);
  
  USTR_CONF_VSNPRINTF_END(ustr_wstr(*ps1), rc + 1, fmt, ap);

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_set_vfmt_lim(struct Ustr **ps1, size_t lim,
                                        const char *fmt, va_list ap)
{ return (ustrp__set_vfmt_lim(0, ps1, lim, fmt, ap)); }
USTR_CONF_I_PROTO
int ustrp_set_vfmt_lim(struct Ustr_pool *p,struct Ustrp **ps1, size_t lim,
                       const char *fmt, va_list ap)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__set_vfmt_lim(p, &tmp, lim, fmt, ap);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_I_PROTO
int ustr_set_fmt_lim(struct Ustr **ps1, size_t lim, const char *fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustr_set_vfmt_lim(ps1, lim, fmt, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO
int ustrp_set_fmt_lim(struct Ustr_pool *p, struct Ustrp **ps1, size_t lim,
                      const char*fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustrp_set_vfmt_lim(p, ps1, lim, fmt, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO int ustr_set_vfmt(struct Ustr **ps1,
                                    const char *fmt, va_list ap)
{ return (ustr_set_vfmt_lim(ps1, 0, fmt, ap)); }

USTR_CONF_I_PROTO int ustrp_set_vfmt(struct Ustr_pool *p, struct Ustrp **ps1,
                                     const char *fmt, va_list ap)
{ return (ustrp_set_vfmt_lim(p, ps1, 0, fmt, ap)); }

USTR_CONF_I_PROTO int ustr_set_fmt(struct Ustr **ps1, const char *fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustr_set_vfmt(ps1, fmt, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO int ustrp_set_fmt(struct Ustr_pool *p, struct Ustrp **ps1,
                                    const char *fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustrp_set_vfmt(p, ps1, fmt, ap);
  va_end(ap);
  
  return (ret);
}
# endif
#endif
