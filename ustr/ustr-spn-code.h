/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_SPN_H
#error " You should have already included ustr-spn.h, or just include ustr.h."
#endif

#ifndef USTR_SRCH_H
#error " You should have already included ustr-srch.h, or just include ustr.h."
#endif

USTR_CONF_I_PROTO
size_t ustr_spn_chr_fwd(const struct Ustr *s1, size_t off, char chr)
{
  const char *ptr = 0;
  size_t len = 0;
  size_t clen = 0;

  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = ustr_cstr(s1);
  len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  ptr += off;
  len -= off;

  clen = len;
  while (len)
  {
    if (*ptr != chr)
      break;

    ++ptr;
    --len;
  }

  return (clen - len);
}

USTR_CONF_I_PROTO
size_t ustr_spn_chr_rev(const struct Ustr *s1, size_t off, char chr)
{
  const char *ptr = 0;
  size_t len = 0;
  size_t clen = 0;

  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = ustr_cstr(s1);
  len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  clen = len;
  ptr += len;
  while (len)
  {
    --ptr;
    
    if (*ptr != chr)
      break;

    --len;
  }

  return (clen - len);
}

USTR_CONF_I_PROTO size_t ustr_spn_chrs_fwd(const struct Ustr *s1, size_t off,
                                           const char *chrs, size_t slen)
{
  const char *ptr = 0;
  size_t len = 0;
  size_t clen = 0;
  
  USTR_ASSERT(chrs);

  if (slen == 1)
    return (ustr_spn_chr_fwd(s1, off, *chrs));

  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = ustr_cstr(s1);
  len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  ptr += off;
  len -= off;

  clen = len;
  while (len)
  {
    if (!memchr(chrs, *ptr, slen))
      break;

    ++ptr;
    --len;
  }

  return (clen - len);
}

USTR_CONF_I_PROTO size_t ustr_spn_chrs_rev(const struct Ustr *s1, size_t off,
                                           const char *chrs, size_t slen)
{
  const char *ptr = 0;
  size_t len = 0;
  size_t clen = 0;
  
  USTR_ASSERT(chrs);

  if (slen == 1)
    return (ustr_spn_chr_rev(s1, off, *chrs));

  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = ustr_cstr(s1);
  len = clen = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  clen = len;
  ptr += len;
  while (len)
  {
    --ptr;
    
    if (!memchr(chrs, *ptr, slen))
      break;

    --len;
  }

  return (clen - len);
}

USTR_CONF_I_PROTO
size_t ustr_cspn_chr_fwd(const struct Ustr *s1, size_t off, char chr)
{
  size_t f_pos = ustr_srch_chr_fwd(s1, off, chr);

  if (!f_pos)
    return (ustr_len(s1) - off);
    
  return (f_pos - off - 1);
}

USTR_CONF_I_PROTO
size_t ustr_cspn_chr_rev(const struct Ustr *s1, size_t off, char chr)
{
  size_t f_pos = ustr_srch_chr_rev(s1, off, chr);

  if (!f_pos)
    return (ustr_len(s1) - off);
    
  return ((ustr_len(s1) - f_pos) - off);
}

USTR_CONF_I_PROTO size_t ustr_cspn_chrs_fwd(const struct Ustr *s1, size_t off,
                                            const char *chrs, size_t slen)
{
  const char *ptr = 0;
  size_t len = 0;
  size_t clen = 0;
  
  USTR_ASSERT(chrs);

  if (slen == 1)
    return (ustr_cspn_chr_fwd(s1, off, *chrs));

  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = ustr_cstr(s1);
  len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  ptr += off;
  len -= off;

  clen = len;
  while (len)
  {
    if (memchr(chrs, *ptr, slen))
      break;

    ++ptr;
    --len;
  }

  return (clen - len);
}

USTR_CONF_I_PROTO size_t ustr_cspn_chrs_rev(const struct Ustr *s1, size_t off,
                                            const char *chrs, size_t slen)
{
  const char *ptr = 0;
  size_t len = 0;
  size_t clen = 0;
  
  USTR_ASSERT(chrs);

  if (slen == 1)
    return (ustr_cspn_chr_rev(s1, off, *chrs));

  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = ustr_cstr(s1);
  len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  len -= off;

  clen = len;
  ptr += len;
  while (len)
  {
    --ptr;
    
    if (memchr(chrs, *ptr, slen))
      break;

    --len;
  }

  return (clen - len);
}

#ifdef USTR_UTF8_H
USTR_CONF_I_PROTO size_t ustr_utf8_spn_chrs_fwd(const struct Ustr*s1,size_t off,
                                                const char *pchrs, size_t slen)
{
  const unsigned char *chrs = (const unsigned char *)pchrs;
  const unsigned char *ptr = 0;
  size_t ret = 0;
  
  USTR_ASSERT(chrs);
  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = (const unsigned char *)ustr_cstr(s1);

  if (off)
    off = ustr_utf8_chars2bytes(s1, 1, off, 0);
  ptr += off;

  while (*ptr)
  {
    const unsigned char *bptr = ptr;

    ptr = ustr__utf8_next(ptr);
    if (!ptr || !USTR__SYS_MEMMEM(chrs, slen, bptr, ptr - bptr))
      break;
    
    ++ret;
  }

  return (ret);
}

USTR_CONF_I_PROTO size_t ustr_utf8_spn_chrs_rev(const struct Ustr*s1,size_t off,
                                                const char *pchrs, size_t slen)
{
  const unsigned char *chrs = (const unsigned char *)pchrs;
  const unsigned char *ptr = 0;
  size_t len = 0;
  size_t ret = 0;
  
  USTR_ASSERT(chrs);
  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = (const unsigned char *)ustr_cstr(s1);
  len = ustr_len(s1);

  if (off)
  {
    size_t ulen = ustr_utf8_len(s1);
    size_t dummy;
    off = ustr_utf8_chars2bytes(s1, ulen - off, off, &dummy);
  }
  len -= off;
  
  while (len)
  {
    const unsigned char *eptr = ptr + len;
    const unsigned char *bptr = ustr__utf8_prev(eptr, len);

    if (!bptr || !USTR__SYS_MEMMEM(chrs, slen, bptr, eptr - bptr))
      break;
    
    ++ret;
    len -= (eptr - bptr);
  }

  return (ret);
}

USTR_CONF_I_PROTO
size_t ustr_utf8_cspn_chrs_fwd(const struct Ustr *s1, size_t off,
                               const char *pchrs, size_t slen)
{
  const unsigned char *chrs = (const unsigned char *)pchrs;
  const unsigned char *ptr = 0;
  size_t ret = 0;
  
  USTR_ASSERT(chrs);
  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = (const unsigned char *)ustr_cstr(s1);

  if (off)
    off = ustr_utf8_chars2bytes(s1, 1, off, 0);
  ptr += off;

  while (*ptr)
  {
    const unsigned char *bptr = ptr;

    ptr = ustr__utf8_next(ptr);
    if (USTR__SYS_MEMMEM(chrs, slen, bptr, ptr - bptr))
      break;
    
    ++ret;
  }

  return (ret);
}

USTR_CONF_I_PROTO
size_t ustr_utf8_cspn_chrs_rev(const struct Ustr *s1, size_t off,
                               const char *pchrs, size_t slen)
{
  const unsigned char *chrs = (const unsigned char *)pchrs;
  const unsigned char *ptr = 0;
  size_t len = 0;
  size_t ret = 0;
  
  USTR_ASSERT(chrs);
  USTR_ASSERT(ustr_assert_valid(s1));

  ptr = (const unsigned char *)ustr_cstr(s1);
  len = ustr_len(s1);

  if (off)
  {
    size_t ulen = ustr_utf8_len(s1);
    size_t dummy;
    off = ustr_utf8_chars2bytes(s1, ulen - off, off, &dummy);
  }
  len -= off;
    
  while (len)
  {
    const unsigned char *eptr = ptr + len;
    const unsigned char *bptr = ustr__utf8_prev(eptr, len);

    if (!bptr || USTR__SYS_MEMMEM(chrs, slen, bptr, eptr - bptr))
      break;
    
    ++ret;
    len -= (eptr - bptr);
  }

  return (ret);
}
#endif
