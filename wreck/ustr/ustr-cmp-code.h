/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_CMP_H
#error " You should have already included ustr-cmp.h, or just include ustr.h."
#endif

USTR_CONF_I_PROTO
int ustr_cmp_buf(const struct Ustr *s1, const void *buf, size_t len2)
{
  size_t len1 = 0;
  size_t lenm = 0;
  int    ret = 0;
  int    def = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1) && buf);

  len1 = ustr_len(s1);
  if (len1 == len2)
    return (memcmp(ustr_cstr(s1), buf, len1));

  if (len1 > len2)
  {
    lenm = len2;
    def  =  1;
  }
  else
  {
    lenm = len1;
    def  = -1;
  }

  if (lenm && (ret = memcmp(ustr_cstr(s1), buf, lenm)))
    return (ret);
  
  return (def);
}

USTR_CONF_I_PROTO
int ustr_cmp_subustr(const struct Ustr *s1,
                     const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));

  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_cmp_buf(s1, "", 0));

  return (ustr_cmp_buf(s1, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_i_PROTO
int ustr__memcasecmp(const void *passed_s1, const void *passed_s2, size_t len)
{
  const unsigned char *s1 = passed_s1;
  const unsigned char *s2 = passed_s2;

  while (len)
  {
    unsigned char c1 = *s1;
    unsigned char c2 = *s2;

    if ((c1 >= 0x61) && (c1 <= 0x7a))
      c1 ^= 0x20;
    if ((c2 >= 0x61) && (c2 <= 0x7a))
      c2 ^= 0x20;
    
    if (c1 != c2)
      return (c1 - c2);

    ++s1;
    ++s2;
    --len;
  }

  return (0);
}

USTR_CONF_I_PROTO
int ustr_cmp_case_buf(const struct Ustr *s1, const void *buf, size_t len2)
{
  size_t len1 = 0;
  size_t lenm = 0;
  int    ret = 0;
  int    def = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1) && buf);

  len1 = ustr_len(s1);
  if (len1 == len2)
    return (ustr__memcasecmp(ustr_cstr(s1), buf, len1));

  if (len1 > len2)
  {
    lenm = len2;
    def  =  1;
  }
  else
  {
    lenm = len1;
    def  = -1;
  }

  if (lenm && (ret = ustr__memcasecmp(ustr_cstr(s1), buf, lenm)))
    return (ret);
  
  return (def);
}

USTR_CONF_I_PROTO
int ustr_cmp_case_subustr(const struct Ustr *s1,
                          const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));

  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_cmp_case_buf(s1, "", 0));

  return (ustr_cmp_case_buf(s1, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_I_PROTO int ustr_cmp_case_prefix_buf_eq(const struct Ustr *s1,
                                                  const void *buf, size_t len2)
{
  size_t len1 = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1) && buf);
  
  len1 = ustr_len(s1);
  if (len1 < len2)
    return (USTR_FALSE);
  
  return (!ustr__memcasecmp(ustr_cstr(s1), buf, len2));
}

USTR_CONF_I_PROTO int ustr_cmp_case_suffix_buf_eq(const struct Ustr *s1,
                                                  const void *buf, size_t len2)
{
  size_t len1 = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1) && buf);
  
  len1 = ustr_len(s1);
  if (len1 < len2)
    return (USTR_FALSE);
  
  return (!ustr__memcasecmp(ustr_cstr(s1) + (len1 - len2), buf, len2));
}

USTR_CONF_I_PROTO
int ustr_cmp_fast_subustr(const struct Ustr *s1,
                          const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));

  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_cmp_fast_buf(s1, "", 0));

  return (ustr_cmp_fast_buf(s1, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_I_PROTO
int ustr_cmp_prefix_subustr_eq(const struct Ustr *s1,
                               const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));

  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_cmp_prefix_buf_eq(s1, "", 0));

  return (ustr_cmp_prefix_buf_eq(s1, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_I_PROTO
int ustr_cmp_suffix_subustr_eq(const struct Ustr *s1,
                               const struct Ustr *s2, size_t pos, size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));

  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_cmp_suffix_buf_eq(s1, "", 0));

  return (ustr_cmp_suffix_buf_eq(s1, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_I_PROTO
int ustr_cmp_case_prefix_subustr_eq(const struct Ustr *s1,
                                    const struct Ustr *s2,size_t pos,size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));

  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_cmp_case_prefix_buf_eq(s1, "", 0));

  return (ustr_cmp_case_prefix_buf_eq(s1, ustr_cstr(s2) + --pos, len));
}

USTR_CONF_I_PROTO
int ustr_cmp_case_suffix_subustr_eq(const struct Ustr *s1,
                                    const struct Ustr *s2,size_t pos,size_t len)
{
  USTR_ASSERT(ustr_assert_valid(s1) && ustr_assert_valid(s2));

  if (!ustr_assert_valid_subustr(s2, pos, len))
    return (ustr_cmp_case_suffix_buf_eq(s1, "", 0));

  return (ustr_cmp_case_suffix_buf_eq(s1, ustr_cstr(s2) + --pos, len));
}

