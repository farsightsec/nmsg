/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_REPLACE_H
#error " Include ustr-replace.h before this file."
#endif

USTR_CONF_i_PROTO
size_t ustrp__replace_inline_buf(struct Ustr_pool *p, struct Ustr **ps1,
                                 const void *optr, size_t olen,
                                 const void *nptr, size_t nlen, size_t lim)
{ /* "fast path" ... we can't fail, so ignore the return values */
  size_t num  = 0;
  size_t pos  = 0;
  
  USTR_ASSERT(ustr_owner(*ps1));
  USTR_ASSERT((nlen == olen) || !ustr_alloc(*ps1));

  while ((pos = ustr_srch_buf_fwd(*ps1, pos, optr, olen)))
  {
    USTR_ASSERT((nlen == olen) ||
                (ustr_fixed(*ps1) &&
                 (ustr_size(*ps1) >= (ustr_len(*ps1) + (nlen - olen)))));
    
    ustrp__sc_sub_buf(p, ps1, pos, olen, nptr, nlen);
    pos += nlen - 1;
    
    ++num;
    if (lim && (num == lim))
      break;
  }
  
  if (!num)
    errno = 0; /* only way to tell between FAILURE and NO REPLACEMENTS */
  return (num);
}


USTR_CONF_i_PROTO
size_t ustrp__replace_buf(struct Ustr_pool *p, struct Ustr **ps1,
                          const void *optr, size_t olen,
                          const void *nptr, size_t nlen, size_t lim)
{
  size_t num  = 0;
  size_t tlen = 0;
  size_t pos  = 0;
  struct Ustr *ret = USTR_NULL;
  const char *rptr;
  size_t lpos = 0;
  size_t roff = 0;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  
  if ((nlen == olen) && ustr_owner(*ps1))
    return (ustrp__replace_inline_buf(p, ps1, optr, olen, nptr, nlen, lim));
  
  /* pre-calc size, and do single alloc and then memcpy.
   * Using dup()/ustr_sc_sub() is much simpler but very slow
   * for large strings. */
  tlen = ustr_len(*ps1);
  while ((pos = ustr_srch_buf_fwd(*ps1, pos, optr, olen)))
  {
    pos += olen - 1;

    if (nlen < olen) /* can go up or down */
      tlen -= (olen - nlen);
    else
    {
      if (tlen > (tlen + (nlen - olen)))
      {
        errno = USTR__ENOMEM;
        return (0);
      }
      tlen += (nlen - olen);
    }

    ++num;
    if (lim && (num == lim))
      break;
  }

  if (!num) /* minor speed hack */
  {
    errno = 0; /* only way to tell between FAILURE and NO REPLACEMENTS */
    return (0);
  }
  
  if (!tlen) /* minor speed hack */
    return (ustrp__del(p, ps1, ustr_len(*ps1)) ? num : 0);
  
  if (ustr_fixed(*ps1) && ((num <= 2) || ustr_limited(*ps1)))
  { /* if we will have to memmove() a lot, double copy */
    if (tlen <= ustr_size(*ps1))
      return (ustrp__replace_inline_buf(p, ps1, optr, olen, nptr, nlen, lim));
    if (ustr_limited(*ps1))
      goto fail_alloc;
  }
  
  if (!(ret = ustrp__dupx_undef(p, USTR__DUPX_FROM(*ps1), tlen)))
    goto fail_alloc;
  
  rptr = ustr_cstr(*ps1);
  lpos = 1;
  roff = 0;
  pos  = 0;
  num  = 0;
  while ((pos = ustr_srch_buf_fwd(*ps1, pos, optr, olen)))
  {
    const char *tptr = rptr + roff;
    size_t blen = pos - (roff + 1);
    
    pos += olen - 1;
    USTR_ASSERT(pos == (roff + blen + olen));
    
    ustrp__sub_buf(p, &ret, lpos, tptr, blen); lpos += blen;
    ustrp__sub_buf(p, &ret, lpos, nptr, nlen); lpos += nlen;

    roff = pos;
    
    ++num;
    if (lim && (num == lim))
      break;
  }
  ustrp__sub_buf(p, &ret, lpos, rptr + roff, ustr_len(*ps1) - roff);

  if (!ustr_fixed(*ps1) || (tlen > ustr_size(*ps1)))
    ustrp__sc_free2(p, ps1, ret);
  else
  { /* fixed buffer, with multiple replacements ... but fits */
    ustrp__set(p, ps1, ret);
    ustrp__free(p, ret);
  }
  
  return (num);

 fail_alloc:
  ustr_setf_enomem_err(*ps1);
  return (0);
}

USTR_CONF_I_PROTO
size_t ustr_replace_buf(struct Ustr **ps1, const void *optr, size_t olen,
                        const void *nptr, size_t nlen, size_t lim)
{ return (ustrp__replace_buf(0, ps1, optr, olen, nptr, nlen, lim)); }
USTR_CONF_I_PROTO
size_t ustrp_replace_buf(struct Ustr_pool *p, struct Ustrp **ps1,
                         const void *optr, size_t olen,
                         const void *nptr, size_t nlen, size_t lim)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__replace_buf(p, &tmp, optr, olen, nptr, nlen, lim);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
size_t ustrp__replace(struct Ustr_pool *p, struct Ustr **ps1,
                      const struct Ustr *srch,
                      const struct Ustr *repl, size_t lim)
{
  struct Ustr *t1 = USTR_NULL;
  struct Ustr *t2 = USTR_NULL;
  size_t ret = 0;
  
  USTR_ASSERT(ustrp__assert_valid(!!p, srch));
  USTR_ASSERT(ustrp__assert_valid(!!p, repl));

  if (srch == *ps1) srch = t1 = ustrp__dup(p, *ps1);
  if (repl == *ps1) repl = t2 = ustrp__dup(p, *ps1);

  if (srch && repl)
    ret = ustrp__replace_buf(p, ps1,
                             ustr_cstr(srch), ustr_len(srch),
                             ustr_cstr(repl), ustr_len(repl), lim);
  
  ustrp__free(p, t1);
  ustrp__free(p, t2);
  
  return (ret);
}
USTR_CONF_I_PROTO
size_t ustr_replace(struct Ustr **ps1, const struct Ustr *srch,
                    const struct Ustr *repl, size_t lim)
{ return (ustrp__replace(0, ps1, srch, repl, lim)); }
USTR_CONF_I_PROTO
size_t ustrp_replace(struct Ustr_pool *p, struct Ustrp **ps1,
                     const struct Ustrp *srch,
                     const struct Ustrp *repl, size_t lim)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__replace(p, &tmp, &srch->s, &repl->s, lim);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
size_t ustrp__replace_inline_rep_chr(struct Ustr_pool *p, struct Ustr **ps1,
                                     char odata, size_t olen, 
                                     char ndata, size_t nlen, size_t lim)
{ /* "fast path" ... as we can't fail after we are the owner(). In theory
   * we can do nlen <= olen, but then we'll spend a lot of time calling
   * memmove(). Which might be painful, so let that fall through to dupx(). */
  size_t num  = 0;
  size_t pos  = 0;

  USTR_ASSERT(ustr_owner(*ps1));
  USTR_ASSERT((nlen == olen) || !ustr_alloc(*ps1));

  while ((pos = ustr_srch_rep_chr_fwd(*ps1, pos, odata, olen)))
  {
    USTR_ASSERT((nlen == olen) ||
                (ustr_fixed(*ps1) &&
                 (ustr_size(*ps1) >= (ustr_len(*ps1) + (nlen - olen)))));
    
    ustrp__sc_sub_rep_chr(p, ps1, pos, olen, ndata, nlen);
    pos += nlen - 1;
    
    ++num;
    if (lim && (num == lim))
      break;
  }

  if (!num)
    errno = 0; /* only way to tell between FAILURE and NO REPLACEMENTS */
  return (num);
}

USTR_CONF_i_PROTO
size_t ustrp__replace_rep_chr(struct Ustr_pool *p, struct Ustr **ps1,
                              char odata, size_t olen, 
                              char ndata, size_t nlen, size_t lim)
{
  size_t num  = 0;
  size_t tlen = 0;
  size_t pos  = 0;
  struct Ustr *ret = USTR_NULL;
  const char *rptr;
  size_t lpos = 0;
  size_t roff = 0;

  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  
  if ((nlen == olen) && ustr_owner(*ps1))
    return (ustrp__replace_inline_rep_chr(p, ps1, odata,olen, ndata,nlen, lim));

  /* pre-calc size, and do single alloc and then memcpy.
   * Using dup()/ustr_sc_sub() is much simpler but very slow
   * for large strings. */
  tlen = ustr_len(*ps1);
  while ((pos = ustr_srch_rep_chr_fwd(*ps1, pos, odata, olen)))
  {
    pos += olen - 1;

    if (nlen < olen) /* can go up or down */
      tlen -= (olen - nlen);
    else
    {
      if (tlen > (tlen + (nlen - olen)))
      {
        errno = USTR__ENOMEM;
        return (0);
      }
      tlen += (nlen - olen);
    }

    ++num;
    if (lim && (num == lim))
      break;
  }

  if (!num) /* minor speed hack */
  {
    errno = 0; /* only way to tell between FAILURE and NO REPLACEMENTS */
    return (0);
  }
  
  if (!tlen) /* minor speed hack */
    return (ustrp__del(p, ps1, ustr_len(*ps1)) ? num : 0);
  
  if (ustr_fixed(*ps1) && ((num <= 2) || ustr_limited(*ps1)))
  { /* if we will have to memmove() a lot, double copy */
    if (tlen <= ustr_size(*ps1))
      return (ustrp__replace_inline_rep_chr(p, ps1, odata,olen,ndata,nlen,lim));
    
    if (ustr_limited(*ps1))
      goto fail_alloc;
  }
  
  if (!(ret = ustrp__dupx_undef(p, USTR__DUPX_FROM(*ps1), tlen)))
    goto fail_alloc;
  
  rptr = ustr_cstr(*ps1);
  lpos = 1;
  roff = 0;
  pos  = 0;
  num  = 0;
  while ((pos = ustr_srch_rep_chr_fwd(*ps1, pos, odata, olen)))
  {
    const char *tptr = rptr + roff;
    size_t blen = pos - (roff + 1);
    
    pos += olen - 1;
    USTR_ASSERT(pos == (roff + blen + olen));
    
    ustrp__sub_buf(p, &ret,     lpos, tptr,  blen); lpos += blen;
    ustrp__sub_rep_chr(p, &ret, lpos, ndata, nlen); lpos += nlen;

    roff = pos;
    
    ++num;
    if (lim && (num == lim))
      break;
  }
  ustrp__sub_buf(p, &ret, lpos, rptr + roff, ustr_len(*ps1) - roff);
  
  if (!ustr_fixed(*ps1) || (tlen > ustr_size(*ps1)))
    ustrp__sc_free2(p, ps1, ret);
  else
  { /* fixed buffer, with multiple replacements ... but fits */
    ustrp__set(p, ps1, ret);
    ustrp__free(p, ret);
  }
  
  return (num);

 fail_alloc:
  ustr_setf_enomem_err(*ps1);
  return (0);
}
USTR_CONF_I_PROTO
size_t ustr_replace_rep_chr(struct Ustr **ps1, char odata, size_t olen, 
                            char ndata, size_t nlen, size_t lim)
{ return (ustrp__replace_rep_chr(0, ps1, odata, olen, ndata, nlen, lim)); }
USTR_CONF_I_PROTO
size_t ustrp_replace_rep_chr(struct Ustr_pool *p, struct Ustrp **ps1,
                             char odata, size_t olen, 
                             char ndata, size_t nlen, size_t lim)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__replace_rep_chr(p, &tmp, odata, olen, ndata, nlen, lim);
  *ps1 = USTRP(tmp);
  return (ret);
}
