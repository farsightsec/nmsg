/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_INS_H
#error " Include ustr-ins.h before this file."
#endif


USTR_CONF_I_PROTO
int ustrp__ins_undef(struct Ustr_pool*p,struct Ustr **ps1,size_t pos,size_t len)
{ /* basically the opposite of ustr_del_subustr() */
  struct Ustr *s1  = USTR_NULL;
  struct Ustr *ret = USTR_NULL;
  size_t clen = 0;
  size_t nlen = 0;
  size_t sz   = 0;
  size_t oh   = 0;
  size_t osz  = 0;
  size_t nsz  = 0;
  int alloc = USTR_FALSE;
  const char *ocstr = 0;

  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  
  if (!len)
    return (USTR_TRUE);

  s1   = *ps1;
  clen = ustr_len(s1);
  USTR_ASSERT_RET(pos <= clen, USTR_FALSE);
  if (pos == clen) /* inserting at the end */
    return (ustrp__add_undef(p, ps1, len));
  
  if ((nlen = clen + len) < clen) /* overflow */
    goto fail_enomem;

  if (ustr__rw_mod(*ps1, nlen, &sz, &oh, &osz, &nsz, &alloc))
  {
    char *ptr;
    
    if (!ustrp__add_undef(p, ps1, len))
      return (USTR_FALSE);

    ptr = ustr_wstr(*ps1);
    memmove(ptr + pos + len, ptr + pos, (clen - pos));

    USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
    return (USTR_TRUE);
  }
    
  if (!(ret = ustrp__dupx_undef(p, USTR__DUPX_FROM(s1), nlen)))
    goto fail_enomem;

  ocstr = ustr_cstr(s1);

  USTR_ASSERT(pos || (clen - pos)); /* can be both */
  
  ustr__memcpy(ret, 0,         ocstr,              pos);
  ustr__memcpy(ret, pos + len, ocstr + pos, clen - pos);

  ustrp__sc_free2(p, ps1, ret);

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  return (USTR_TRUE);

 fail_enomem:
  ustr_setf_enomem_err(s1);
  return (USTR_FALSE);
}
USTR_CONF_I_PROTO int ustr_ins_undef(struct Ustr **ps1, size_t pos, size_t len)
{ return (ustrp__ins_undef(0, ps1, pos, len)); }
USTR_CONF_I_PROTO
int ustrp_ins_undef(struct Ustr_pool *p,struct Ustrp**ps1,size_t pos,size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__ins_undef(p, &tmp, pos, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__ins_buf(struct Ustr_pool *p, struct Ustr **ps1,
                                     size_t pos, const void *buf, size_t len)
{
  if (!ustrp__ins_undef(p, ps1, pos, len))
    return (USTR_FALSE);
  
  ustr__memcpy(*ps1, pos, buf, len);

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO
int ustr_ins_buf(struct Ustr **ps1, size_t pos, const void *buf, size_t len)
{ return (ustrp__ins_buf(0, ps1, pos, buf, len)); }
USTR_CONF_I_PROTO int ustrp_ins_buf(struct Ustr_pool *p, struct Ustrp **ps1,
                                    size_t pos, const void *buf, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__ins_buf(p, &tmp, pos, buf, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__ins(struct Ustr_pool *p, struct Ustr **ps1,
                                 size_t pos, const struct Ustr *s2)
{
  if (pos == ustr_len(*ps1))
    return (ustrp__add(p, ps1, s2));
  
  if ((*ps1 == s2) && ustr_owner(*ps1))
  {
    size_t len = ustr_len(*ps1);
    size_t blen = 0;
    size_t pos2 = 0;
    
    if (!ustrp__ins_undef(p, ps1, pos, len))
      return (USTR_FALSE);

    blen = pos;
    ustr__memcpy(*ps1, pos, ustr_cstr(*ps1), blen);
    pos  += blen;
    pos2 +=  len;
    pos2 += blen;
    len  -= blen;
    ustr__memcpy(*ps1, pos, ustr_cstr(*ps1) + pos2, len);
    USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
    
    return (USTR_TRUE);
  }

  return (ustrp__ins_buf(p, ps1, pos, ustr_cstr(s2), ustr_len(s2)));
}
USTR_CONF_I_PROTO
int ustr_ins(struct Ustr **ps1, size_t pos, const struct Ustr *s2)
{ return (ustrp__ins(0, ps1, pos, s2)); }
USTR_CONF_I_PROTO int ustrp_ins(struct Ustr_pool *p, struct Ustrp **ps1,
                                size_t pos, const struct Ustrp *s2)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__ins(p, &tmp, pos, &s2->s);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__ins_subustr(struct Ustr_pool *p, struct Ustr **ps1, size_t pos1,
                       const struct Ustr *s2, size_t pos2, size_t len2)
{
  size_t clen2 = 0;

  if (!len2)
    return (USTR_TRUE);
  
  if (!(clen2 = ustrp__assert_valid_subustr(!!p, s2, pos2, len2)))
    return (USTR_FALSE);

  if (clen2 == len2)
    return (ustrp__ins(p, ps1, pos1, s2));

  if (pos1 == clen2)
    return (ustrp__add_subustr(p, ps1, s2, pos2, len2));
  
  if ((*ps1 == s2) && ustr_owner(*ps1))
  {
    if (!ustrp__ins_undef(p, ps1, pos1, len2))
      return (USTR_FALSE);

    if (pos2 > pos1)
      pos2 += len2;
    else if ((pos2 + len2 - 1) > pos1)
    {
      size_t blen = (pos1 - pos2) + 1;

      ustr__memcpy(*ps1, pos1, ustr_cstr(*ps1) + pos2 - 1, blen);
      pos1 += blen;
      pos2 += len2;
      pos2 += blen;
      len2 -= blen;
    }
      ustr__memcpy(*ps1, pos1, ustr_cstr(*ps1) + pos2 - 1, len2);
      
      USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
    return (USTR_TRUE);
  }

  --pos2;  
  return (ustrp__ins_buf(p, ps1, pos1, ustr_cstr(s2) + pos2, len2));
}
USTR_CONF_I_PROTO
int ustr_ins_subustr(struct Ustr **ps1, size_t pos1,
                     const struct Ustr *s2, size_t pos2, size_t len2)
{ return (ustrp__ins_subustr(0, ps1, pos1, s2, pos2, len2)); }
USTR_CONF_I_PROTO
int ustrp_ins_subustrp(struct Ustr_pool *p, struct Ustrp **ps1, size_t pos1,
                       const struct Ustrp *s2, size_t pos2, size_t len2)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__ins_subustr(p, &tmp, pos1, &s2->s, pos2, len2);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__ins_rep_chr(struct Ustr_pool *p, struct Ustr **ps1,
                                         size_t pos, char chr, size_t len)
{
  if (!ustrp__ins_undef(p, ps1, pos, len))
    return (USTR_FALSE);
  
  ustr__memset(*ps1, pos, chr, len);

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO
int ustr_ins_rep_chr(struct Ustr **ps1, size_t pos, char chr, size_t len)
{ return (ustrp__ins_rep_chr(0, ps1, pos, chr, len)); }
USTR_CONF_I_PROTO int ustrp_ins_rep_chr(struct Ustr_pool *p, struct Ustrp **ps1,
                                        size_t pos, char chr, size_t len)

{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__ins_rep_chr(p, &tmp, pos, chr, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

#ifdef USTR_FMT_H
# if USTR_CONF_HAVE_VA_COPY
USTR_CONF_i_PROTO
int ustrp__ins_vfmt_lim(struct Ustr_pool *p, struct Ustr **ps1, size_t pos,
                        size_t lim, const char *fmt, va_list ap)
{ /* NOTE: Copy and pasted so we can use ustrp_set_undef() */
  va_list nap;
  int rc = -1;
  char buf[USTR__SNPRINTF_LOCAL];
  char *ptr;
  char save_end;
  
  USTR__VA_COPY(nap, ap);
  rc = USTR_CONF_VSNPRINTF_BEG(buf, sizeof(buf), fmt, nap);
  va_end(nap);

  if ((rc == -1) && ((rc = ustr__retard_vfmt_ret(fmt, ap)) == -1))
    return (USTR_FALSE);

  if (lim && ((size_t)rc > lim))
    rc = lim;
  
  if ((size_t)rc < sizeof(buf)) /* everything is done */
    return (ustrp__ins_buf(p, ps1, pos, buf, rc));
  
  if (!ustrp__ins_undef(p, ps1, pos, rc))
    return (USTR_FALSE);

  ptr = ustr_wstr(*ps1);

  save_end = ptr[pos + rc]; /* might be NIL, might be a char */
  USTR_CONF_VSNPRINTF_END(ptr + pos, rc + 1, fmt, ap);
  ptr[pos + rc] = save_end;

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_ins_vfmt_lim(struct Ustr **ps1,size_t pos,size_t lim,
                                        const char *fmt, va_list ap)
{ return (ustrp__ins_vfmt_lim(0, ps1, pos, lim, fmt, ap)); }
USTR_CONF_I_PROTO
int ustrp_ins_vfmt_lim(struct Ustr_pool *p,struct Ustrp **ps1, size_t pos,
                       size_t lim, const char *fmt, va_list ap)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__ins_vfmt_lim(p, &tmp, pos, lim, fmt, ap);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_I_PROTO int ustr_ins_fmt_lim(struct Ustr **ps1, size_t pos,
                                       size_t lim, const char *fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustr_ins_vfmt_lim(ps1, pos, lim, fmt, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO
int ustrp_ins_fmt_lim(struct Ustr_pool *p, struct Ustrp **ps1, size_t pos,
                      size_t lim, const char*fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustrp_ins_vfmt_lim(p, ps1, pos, lim, fmt, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO int ustr_ins_vfmt(struct Ustr **ps1, size_t pos,
                                    const char *fmt, va_list ap)
{ return (ustr_ins_vfmt_lim(ps1, pos, 0, fmt, ap)); }

USTR_CONF_I_PROTO int ustrp_ins_vfmt(struct Ustr_pool *p, struct Ustrp **ps1,
                                     size_t pos, const char *fmt, va_list ap)
{ return (ustrp_ins_vfmt_lim(p, ps1, pos, 0, fmt, ap)); }

USTR_CONF_I_PROTO
int ustr_ins_fmt(struct Ustr **ps1, size_t pos, const char *fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustr_ins_vfmt(ps1, pos, fmt, ap);
  va_end(ap);
  
  return (ret);
}

USTR_CONF_I_PROTO int ustrp_ins_fmt(struct Ustr_pool *p, struct Ustrp **ps1,
                                    size_t pos, const char *fmt, ...)
{
  va_list ap;
  int ret = USTR_FALSE;
  
  va_start(ap, fmt);
  ret = ustrp_ins_vfmt(p, ps1, pos, fmt, ap);
  va_end(ap);
  
  return (ret);
}
# endif
#endif
