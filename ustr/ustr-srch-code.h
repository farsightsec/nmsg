/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_SRCH_H
#error " Include ustr-srch.h before this file."
#endif

#ifndef USTR_CONF_HAVE_MEMRCHR /* GNU extension */
#ifdef __GLIBC__
#define USTR_CONF_HAVE_MEMRCHR 1
#else
#define USTR_CONF_HAVE_MEMRCHR 0
#endif
#endif

USTR_CONF_I_PROTO
size_t ustr_srch_chr_fwd(const struct Ustr *s1, size_t off, char val)
{
  const char *beg = ustr_cstr(s1);
  const char *ptr;
  size_t len = ustr_len(s1);
  const char *tmp;

  USTR_ASSERT(ustr_assert_valid(s1));

  USTR_ASSERT_RET(off <= len, 0);
  ptr  = beg + off;
  len -= off;

  if (!(tmp = memchr(ptr, val, len))) return (0);

  len = tmp - beg;
  return (len + 1);
}

#if USTR_CONF_HAVE_MEMRCHR /* GNU extension */
USTR_CONF_I_PROTO size_t ustr_srch_chr_rev(const struct Ustr *s1, size_t off,
                                           char val)
{
  const char *ptr = ustr_cstr(s1);
  size_t len = ustr_len(s1);
  const char *tmp;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  if (!(tmp = memrchr(ptr, val, len))) return (0);

  len = tmp - ptr;
  return (len + 1);
}
#else
USTR_CONF_I_PROTO size_t ustr_srch_chr_rev(const struct Ustr *s1, size_t off,
                                           char val)
{ /* slow... */
  const char *ptr = ustr_cstr(s1);
  size_t len = ustr_len(s1);
  const char *tmp = ptr;
  const char *prev = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  while ((tmp = memchr(tmp, val, len - (tmp - ptr))))
  {
    prev = tmp;
    ++tmp;
  }
  
  if (!prev)
    return (0);

  len = prev - ptr;
  return (len + 1);
}
#endif

#if ! USTR_CONF_HAVE_MEMMEM
USTR_CONF_i_PROTO void *ustr__sys_memmem(const void *hs, size_t hslen,
                                         const void *nd, size_t ndlen)
{
  const char *ptr = hs;

  if (ndlen == 0)
    return ((void *)hs);

  while (hslen >= ndlen)
  {
    if (!memcmp(ptr, nd, ndlen))
      return ((void *)ptr);

    --hslen;
    ++ptr;
  }
  
  return (0);
}
#endif

USTR_CONF_I_PROTO size_t ustr_srch_buf_fwd(const struct Ustr *s1, size_t off,
                                           const void *val, size_t vlen)
{
  const char *beg = ustr_cstr(s1);
  const char *ptr;
  size_t len = ustr_len(s1);
  char *tmp = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_chr_fwd(s1, off, ((const char *)val)[0]));

  USTR_ASSERT_RET(off <= len, 0);
  if (vlen == 0)
    return (len ? (off + 1) : 0);
  
  ptr  = beg + off;
  len -= off;

  if (!(tmp = USTR__SYS_MEMMEM(ptr, len, val, vlen)))
    return (0);

  len = tmp - beg;
  return (len + 1);
}

USTR_CONF_I_PROTO size_t ustr_srch_buf_rev(const struct Ustr *s1, size_t off,
                                           const void *val, size_t vlen)
{
  const char *ptr = ustr_cstr(s1);
  size_t len = ustr_len(s1);
  const char *prev = 0;
  const char *tmp  = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_chr_rev(s1, off, ((const char *)val)[0]));

  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  if (vlen == 0)
    return (len);
  
  tmp = ptr;
  while (((len - (tmp - ptr)) >= vlen) &&
         (tmp = USTR__SYS_MEMMEM(tmp, len - (tmp - ptr), val, vlen)))
  {
    prev = tmp;
    ++tmp;
  }
  if (!prev)
    return (0);

  len = prev - ptr;
  return (len + 1);
}

USTR_CONF_I_PROTO
size_t ustr_srch_subustr_fwd(const struct Ustr *s1, size_t off,
                             const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));
  
  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_srch_buf_fwd(s1, off, "", 0));
  
  return (ustr_srch_buf_fwd(s1, off, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_I_PROTO
size_t ustr_srch_subustr_rev(const struct Ustr *s1, size_t off,
                             const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));
  
  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_srch_buf_rev(s1, off, "", 0));
  
  return (ustr_srch_buf_rev(s1, off, ustr_cstr(s2) + --pos, len));  
}

USTR_CONF_i_PROTO
void *ustr__memrepchr(const void *hs, size_t hslen, char nd, size_t ndlen)
{
  const char *ptr = hs;

  USTR_ASSERT(ndlen); /* dealt with by callers */

  while (hslen >= ndlen)
  {
    const char *tmp = memchr(ptr, nd, hslen);
    size_t len = ndlen;
    
    if (!tmp)
      break;
    if (ndlen > (hslen - (tmp - ptr)))
      break;

    tmp += len;
    while (len > 0)
    {
      --tmp;
      if (*tmp != nd)
        break;
      --len;
    }
    if (!len)
      return ((void *)tmp);

    hslen -= (tmp - ptr);
    ptr = tmp;
  }
  
  return (0);
}

USTR_CONF_I_PROTO size_t ustr_srch_rep_chr_fwd(const struct Ustr *s1,size_t off,
                                               char val, size_t vlen)
{
  const char *beg = ustr_cstr(s1);
  const char *ptr;
  size_t len = ustr_len(s1);
  char *tmp = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_chr_fwd(s1, off, val));

  USTR_ASSERT_RET(off <= len, 0);
  if (vlen == 0)
    return (len ? (off + 1) : 0);

  ptr  = beg + off;
  len -= off;

  if (!(tmp = ustr__memrepchr(ptr, len, val, vlen)))
    return (0);

  len = tmp - beg;
  return (len + 1);
}

USTR_CONF_I_PROTO size_t ustr_srch_rep_chr_rev(const struct Ustr *s1,size_t off,
                                               char val, size_t vlen)
{
  const char *ptr = ustr_cstr(s1);
  size_t len = ustr_len(s1);
  const char *prev = 0;
  const char *tmp  = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_chr_rev(s1, off, val));

  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  if (vlen == 0)
    return (len);
  
  tmp = ptr;
  while (((len - (tmp - ptr)) >= vlen) &&
         (tmp = ustr__memrepchr(tmp, len - (tmp - ptr), val, vlen)))
  {
    prev = tmp;
    ++tmp;
  }
  if (!prev)
    return (0);

  len = prev - ptr;
  return (len + 1);
}

/* ignore case */
USTR_CONF_i_PROTO
void *ustr__memcasechr(const void *hs, const char nd, size_t len)
{
  const unsigned char *s1 = hs;
  unsigned char c2 = nd;

  if ((c2 >= 0x61) && (c2 <= 0x7a))
    c2 ^= 0x20;
  
  while (len)
  {
    unsigned char c1 = *s1;

    if ((c1 >= 0x61) && (c1 <= 0x7a))
      c1 ^= 0x20;
    
    if (c1 == c2)
      return ((void *)s1);
    
    --len;
    ++s1;
  }
  
  return (0);
}

USTR_CONF_i_PROTO
void *ustr__memcasemem(const void *hs,size_t hslen, const void *nd,size_t ndlen)
{
  const char *ptr = hs;

  USTR_ASSERT(ndlen); /* dealt with by callers */

  while (hslen >= ndlen)
  {
    if (!ustr__memcasecmp(ptr, nd, ndlen))
      return ((void *)ptr);

    --hslen;
    ++ptr;
  }
  
  return (0);
}

USTR_CONF_i_PROTO
void *ustr__memcaserepchr(const void *hs, size_t hslen, char nd, size_t ndlen)
{
  const unsigned char *s1 = hs;
  unsigned char c2 = nd;

  USTR_ASSERT(ndlen); /* dealt with by callers */

  if ((c2 >= 0x61) && (c2 <= 0x7a))
    c2 ^= 0x20;

  while (hslen >= ndlen)
  {
    const unsigned char *tmp = ustr__memcasechr(s1, nd, hslen);
    size_t len = ndlen;
    
    if (!tmp)
      break;
    if (ndlen > (hslen - (tmp - s1)))
      break;

    tmp += len;
    while (len > 0)
    {
      unsigned char c1 = *--tmp;

      if ((c1 >= 0x61) && (c1 <= 0x7a))
        c1 ^= 0x20;
    
      if (c1 != c2)
        break;
      
      --len;
    }
    if (!len)
      return ((void *)tmp);

    hslen -= (tmp - s1);
    s1 = tmp;
  }
  
  return (0);
}


USTR_CONF_I_PROTO
size_t ustr_srch_case_chr_fwd(const struct Ustr *s1, size_t off, char val)
{
  const char *beg = ustr_cstr(s1);
  const char *ptr;
  size_t len = ustr_len(s1);
  const char *tmp;

  USTR_ASSERT(ustr_assert_valid(s1));

  USTR_ASSERT_RET(off <= len, 0);
  ptr  = beg + off;
  len -= off;

  if (!(tmp = ustr__memcasechr(ptr, val, len))) return (0);

  len = tmp - beg;
  return (len + 1);
}

USTR_CONF_I_PROTO
size_t ustr_srch_case_chr_rev(const struct Ustr *s1, size_t off, char val)
{ /* slow... */
  const char *ptr = ustr_cstr(s1);
  size_t len = ustr_len(s1);
  const char *tmp = ptr;
  const char *prev = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  while ((tmp = ustr__memcasechr(tmp, val, len - (tmp - ptr))))
  {
    prev = tmp;
    ++tmp;
  }
  
  if (!prev)
    return (0);

  len = prev - ptr;
  return (len + 1);
}

USTR_CONF_I_PROTO
size_t ustr_srch_case_buf_fwd(const struct Ustr *s1, size_t off,
                              const void *val, size_t vlen)
{
  const char *beg = ustr_cstr(s1);
  const char *ptr;
  size_t len = ustr_len(s1);
  char *tmp = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_case_chr_fwd(s1, off, ((const char *)val)[0]));

  USTR_ASSERT_RET(off <= len, 0);
  if (vlen == 0)
    return (len ? (off + 1) : 0);
  
  ptr  = beg + off;
  len -= off;

  if (!(tmp = ustr__memcasemem(ptr, len, val, vlen)))
    return (0);

  len = tmp - beg;
  return (len + 1);
}

USTR_CONF_I_PROTO
size_t ustr_srch_case_buf_rev(const struct Ustr *s1, size_t off,
                              const void *val, size_t vlen)
{
  const char *ptr = ustr_cstr(s1);
  size_t len = ustr_len(s1);
  const char *prev = 0;
  const char *tmp  = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_case_chr_rev(s1, off, ((const char *)val)[0]));

  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  if (vlen == 0)
    return (len);

  tmp = ptr;
  while (((len - (tmp - ptr)) >= vlen) &&
         (tmp = ustr__memcasemem(tmp, len - (tmp - ptr), val, vlen)))
  {
    prev = tmp;
    ++tmp;
  }
  if (!prev)
    return (0);

  len = prev - ptr;
  return (len + 1);
}

USTR_CONF_I_PROTO
size_t ustr_srch_case_subustr_fwd(const struct Ustr *s1, size_t off,
                                  const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));
  
  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_srch_case_buf_fwd(s1, off, "", 0));
  
  return (ustr_srch_case_buf_fwd(s1, off, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_I_PROTO
size_t ustr_srch_case_subustr_rev(const struct Ustr *s1, size_t off,
                                  const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));
  
  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_srch_case_buf_rev(s1, off, "", 0));
  
  return (ustr_srch_case_buf_rev(s1, off, ustr_cstr(s2) + --pos, len));  
}

USTR_CONF_I_PROTO
size_t ustr_srch_case_rep_chr_fwd(const struct Ustr *s1, size_t off,
                                  char val, size_t vlen)
{
  const char *beg = ustr_cstr(s1);
  const char *ptr;
  size_t len = ustr_len(s1);
  char *tmp = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_case_chr_fwd(s1, off, val));

  USTR_ASSERT_RET(off <= len, 0);
  if (vlen == 0)
    return (len ? (off + 1) : 0);
  
  ptr  = beg + off;
  len -= off;

  if (!(tmp = ustr__memcaserepchr(ptr, len, val, vlen)))
    return (0);

  len = tmp - beg;
  return (len + 1);
}

USTR_CONF_I_PROTO
size_t ustr_srch_case_rep_chr_rev(const struct Ustr *s1, size_t off,
                                  char val, size_t vlen)
{
  const char *ptr = ustr_cstr(s1);
  size_t len = ustr_len(s1);
  const char *prev = 0;
  const char *tmp  = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (vlen == 1)
    return (ustr_srch_case_chr_rev(s1, off, val));

  USTR_ASSERT_RET(off <= len, 0);
  len -= off;
  
  if (vlen == 0)
    return (len);

  tmp = ptr;
  while (((len - (tmp - ptr)) >= vlen) &&
         (tmp = ustr__memcaserepchr(tmp, len - (tmp - ptr), val, vlen)))
  {
    prev = tmp;
    ++tmp;
  }
  if (!prev)
    return (0);

  len = prev - ptr;
  return (len + 1);
}

