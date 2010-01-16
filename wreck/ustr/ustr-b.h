/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_B_H
#define USTR_B_H 1

#include "ustr-main.h"

#if USTR_CONF_HAVE_STDINT_H

/* ---------------- add ---------------- */
USTR_CONF_EI_PROTO int ustr_add_b_uint16(struct Ustr **, uint_least16_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_add_b_uint32(struct Ustr **, uint_least32_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_add_b_uint64(struct Ustr **, uint_least64_t)
    USTR__COMPILE_ATTR_NONNULL_A();

/* ---------------- parse ---------------- */

USTR_CONF_EI_PROTO uint_least16_t ustr_parse_b_uint16(const struct Ustr*,size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO uint_least32_t ustr_parse_b_uint32(const struct Ustr*,size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO uint_least64_t ustr_parse_b_uint64(const struct Ustr*,size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

/* ---------------- pool APIs ---------------- */

/* ---------------- add ---------------- */
USTR_CONF_EI_PROTO
int ustrp_add_b_uint16(struct Ustr_pool *, struct Ustrp **, uint_least16_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
int ustrp_add_b_uint32(struct Ustr_pool *, struct Ustrp **, uint_least32_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
int ustrp_add_b_uint64(struct Ustr_pool *, struct Ustrp **, uint_least64_t)
    USTR__COMPILE_ATTR_NONNULL_A();


/* ---------------- parse ---------------- */

USTR_CONF_EI_PROTO
uint_least16_t ustrp_parse_b_uint16(const struct Ustrp *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
uint_least32_t ustrp_parse_b_uint32(const struct Ustrp *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
uint_least64_t ustrp_parse_b_uint64(const struct Ustrp *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();


#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO int ustr_add_b_uint16(struct Ustr **ps1, uint_least16_t data)
{
  unsigned char buf[2];

  buf[1] = data & 0xFF; data >>= 8;
  buf[0] = data & 0xFF;

  return (ustr_add_buf(ps1, buf, sizeof(buf)));
}

USTR_CONF_II_PROTO int ustr_add_b_uint32(struct Ustr **ps1, uint_least32_t data)
{
  unsigned char buf[4];

  buf[3] = data & 0xFF; data >>= 8;
  buf[2] = data & 0xFF; data >>= 8;
  buf[1] = data & 0xFF; data >>= 8;
  buf[0] = data & 0xFF;

  return (ustr_add_buf(ps1, buf, sizeof(buf)));
}

USTR_CONF_II_PROTO int ustr_add_b_uint64(struct Ustr **ps1, uint_least64_t data)
{
  unsigned char buf[8];

  buf[7] = data & 0xFF; data >>= 8;
  buf[6] = data & 0xFF; data >>= 8;
  buf[5] = data & 0xFF; data >>= 8;
  buf[4] = data & 0xFF; data >>= 8;

  buf[3] = data & 0xFF; data >>= 8;
  buf[2] = data & 0xFF; data >>= 8;
  buf[1] = data & 0xFF; data >>= 8;
  buf[0] = data & 0xFF;

  return (ustr_add_buf(ps1, buf, sizeof(buf)));
}

USTR_CONF_II_PROTO
uint_least16_t ustr_parse_b_uint16(const struct Ustr *s1, size_t off)
{
  uint_least16_t ret = 0;
  const unsigned char *ptr = 0;
  size_t len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  
  if (len < 2)         return (ret);
  if ((len - 2) < off) return (ret);

  ptr = (const unsigned char *) ustr_cstr(s1);
  ptr += off;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++;

  return (ret);
}

USTR_CONF_II_PROTO
uint_least32_t ustr_parse_b_uint32(const struct Ustr *s1, size_t off)
{
  uint_least32_t ret = 0;
  const unsigned char *ptr = 0;
  size_t len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  
  if (len < 4)         return (ret);
  if ((len - 4) < off) return (ret);

  ptr = (const unsigned char *) ustr_cstr(s1);
  ptr += off;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++;

  return (ret);
}

USTR_CONF_II_PROTO
uint_least64_t ustr_parse_b_uint64(const struct Ustr *s1, size_t off)
{
  uint_least64_t ret = 0;
  const unsigned char *ptr = 0;
  size_t len = ustr_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  
  if (len < 8)         return (ret);
  if ((len - 8) < off) return (ret);

  ptr = (const unsigned char *) ustr_cstr(s1);
  ptr += off;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;

  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++;

  return (ret);
}

/* ----------------------------------------------- */
/* copy and paste the above functions for pool API */
/* ----------------------------------------------- */

USTR_CONF_II_PROTO
int ustrp_add_b_uint16(struct Ustr_pool *p, struct Ustrp **ps1,
                       uint_least16_t data)
{
  unsigned char buf[2];

  buf[1] = data & 0xFF; data >>= 8;
  buf[0] = data & 0xFF;

  return (ustrp_add_buf(p, ps1, buf, sizeof(buf)));
}

USTR_CONF_II_PROTO
int ustrp_add_b_uint32(struct Ustr_pool *p, struct Ustrp **ps1,
                       uint_least32_t data)
{
  unsigned char buf[4];

  buf[3] = data & 0xFF; data >>= 8;
  buf[2] = data & 0xFF; data >>= 8;
  buf[1] = data & 0xFF; data >>= 8;
  buf[0] = data & 0xFF;

  return (ustrp_add_buf(p, ps1, buf, sizeof(buf)));
}

USTR_CONF_II_PROTO
int ustrp_add_b_uint64(struct Ustr_pool *p, struct Ustrp **ps1,
                       uint_least64_t data)
{
  unsigned char buf[8];

  buf[7] = data & 0xFF; data >>= 8;
  buf[6] = data & 0xFF; data >>= 8;
  buf[5] = data & 0xFF; data >>= 8;
  buf[4] = data & 0xFF; data >>= 8;

  buf[3] = data & 0xFF; data >>= 8;
  buf[2] = data & 0xFF; data >>= 8;
  buf[1] = data & 0xFF; data >>= 8;
  buf[0] = data & 0xFF;

  return (ustrp_add_buf(p, ps1, buf, sizeof(buf)));
}

USTR_CONF_II_PROTO
uint_least16_t ustrp_parse_b_uint16(const struct Ustrp *s1, size_t off)
{
  uint_least16_t ret = 0;
  const unsigned char *ptr = 0;
  size_t len = ustrp_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  
  if (len < 2)         return (ret);
  if ((len - 2) < off) return (ret);

  ptr = (const unsigned char *) ustrp_cstr(s1);
  ptr += off;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++;

  return (ret);
}

USTR_CONF_II_PROTO
uint_least32_t ustrp_parse_b_uint32(const struct Ustrp *s1, size_t off)
{
  uint_least32_t ret = 0;
  const unsigned char *ptr = 0;
  size_t len = ustrp_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  
  if (len < 4)         return (ret);
  if ((len - 4) < off) return (ret);

  ptr = (const unsigned char *) ustrp_cstr(s1);
  ptr += off;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++;

  return (ret);
}

USTR_CONF_II_PROTO
uint_least64_t ustrp_parse_b_uint64(const struct Ustrp *s1, size_t off)
{
  uint_least64_t ret = 0;
  const unsigned char *ptr = 0;
  size_t len = ustrp_len(s1);

  USTR_ASSERT_RET(off <= len, 0);
  
  if (len < 8)         return (ret);
  if ((len - 8) < off) return (ret);
  
  ptr = (const unsigned char *) ustrp_cstr(s1);
  ptr += off;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;

  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++; ret <<= 8;
  ret += *ptr++;

  return (ret);
}

#endif

#endif

#endif
