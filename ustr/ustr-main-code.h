/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_MAIN_H
#error " You should have already included ustr-main.h, or just include ustr.h."
#endif

USTR_CONF_i_PROTO
int ustr__dupx_cmp_eq(size_t sz1, size_t rb1, int x1, int emem1,
                      size_t sz2, size_t rb2, int x2, int emem2)
{
  if ((!x1 != !x2) || (!emem1 != !emem2))
    return (USTR_FALSE);
  
  if (sz1)
  {
    if (rb1 < 2)
      rb1 = 2;
  }
  else if (rb1 > 4)
    sz1 = 1;

  if (sz2)
  {
    if (rb2 < 2)
      rb2 = 2;
  }
  else if (rb2 > 4)
    sz2 = 1;

  return ((!sz1 == !sz2) && (rb1 == rb2));
}

USTR_CONF_i_PROTO size_t ustr__sz_get(const struct Ustr *s1)
{
  size_t lenn = 0;
  
  USTR_ASSERT(!ustr_ro(s1));
  USTR_ASSERT( ustr_sized(s1));
  
  lenn = USTR__LEN_LEN(s1);
  
  return (ustr_xi__embed_val_get(s1->data + 1 + USTR__REF_LEN(s1) + lenn,lenn));
}

USTR_CONF_i_PROTO size_t ustr__nb(size_t num)
{
  USTR_ASSERT((num <= 0xFFFFFFFF) || USTR_CONF_HAVE_64bit_SIZE_MAX);
  
  if (num > 0xFFFFFFFF)                 return (8);
  if (num > 0xFFFF)                     return (4);
  if (num > 0xFF)                       return (2);
  else                                  return (1);
}

USTR_CONF_i_PROTO
int ustrp__assert_valid(int p, const struct Ustr *s1)
{
  const char *eos_ptr = 0;
  size_t      eos_len = sizeof(USTR_END_ALOCDx);
  size_t rbytes = 0;
  size_t lbytes = 0;
  size_t sbytes = 0;
  size_t sz = 0;
  size_t oh = 0;
  
  USTR_ASSERT_RET(s1, USTR_FALSE);
  ustr_assert_ret(USTR__ASSERT_MALLOC_CHECK_MEM(p, s1), USTR_FALSE);
  
  if (!s1->data[0])
    return (USTR_TRUE);

  /* just make sure for compound "bits" tests */
  USTR_ASSERT(( ustr_alloc(s1) || ustr_sized(s1)) != ustr_ro(s1));
  USTR_ASSERT((!ustr_alloc(s1) && ustr_sized(s1)) == ustr_fixed(s1));
  USTR_ASSERT(( ustr_fixed(s1) && ustr_exact(s1)) == ustr_limited(s1));
  
  rbytes = USTR__REF_LEN(s1);
  lbytes = USTR__LEN_LEN(s1);
  ustr_assert_ret(lbytes, USTR_FALSE);

  if (ustr_sized(s1))
  {
    sbytes = lbytes;
    sz = ustr__sz_get(s1);
  }
  oh = 1 + rbytes + lbytes + sbytes + eos_len;
  
  USTR_ASSERT_RET(!ustr_sized(s1) || (ustr_len(s1) <= sz), USTR_FALSE);

  USTR_ASSERT(!sz || (ustr__nb(sz) == lbytes) ||
              ((ustr__nb(sz) == 1) && (lbytes == 2))); /* 2 is the minimum */
  
  USTR_ASSERT_RET(!sz || (oh <= sz),                       USTR_FALSE);
  USTR_ASSERT_RET(!sz || ((ustr_len(s1) + oh) <= sz),      USTR_FALSE);
  
  USTR_ASSERT_RET( ustr_exact(s1)  || !ustr_ro(s1),         USTR_FALSE);
  USTR_ASSERT_RET(!ustr_enomem(s1) || !ustr_ro(s1),         USTR_FALSE);

  if (!USTR_CONF_USE_EOS_MARK)
  {
    USTR_ASSERT_RET(!ustr_cstr(s1)[ustr_len(s1)], USTR_FALSE);
    return (USTR_TRUE);
  }
  
  if (ustr_ro(s1))
    eos_ptr = USTR_END_CONSTx;
  else if (ustr_fixed(s1))
    eos_ptr = USTR_END_FIXEDx;
  else
    eos_ptr = USTR_END_ALOCDx;

  USTR_ASSERT_RET(!memcmp(ustr_cstr(s1) + ustr_len(s1), eos_ptr, eos_len),
                  USTR_FALSE);

  return (USTR_TRUE);
}
/* Due to ustrp_assert_valid() being inline we can't pass 0 for
 * ustr_assert_valid() until we've made two ustr_assert_valid() versions.
 * Maybe I'll do that for 1.0.3 ... NOTE: We'd need to change the other
 * internal ustr_assert_valid() calls. */
USTR_CONF_I_PROTO int ustr_assert_valid(const struct Ustr *s1)
{ return (ustrp__assert_valid(1, s1)); }
/* We can't change the API of this function until 2.0.x time, even if we want
 * to. But it's no big deal, as we might not want to. */
USTR_CONF_I_PROTO int ustrp_assert_valid(const struct Ustrp *s1)
{ return (ustrp__assert_valid(1, &s1->s)); }

USTR_CONF_i_PROTO
size_t ustrp__assert_valid_subustr(int p, const struct Ustr *s1,
                                   size_t pos, size_t len)
{
  size_t clen = 0;

  (void) p;
  USTR_ASSERT(ustrp__assert_valid(p, s1));
  USTR_ASSERT_RET(pos, 0);
  
  clen = ustr_len(s1);
  if (((pos == 1) || !len) && (len == clen))
    return (clen);
  
  USTR_ASSERT_RET((clen >= pos), 0);
  USTR_ASSERT_RET((clen >= (len + --pos)), 0);

  return (clen);
}
/* see comments for ustr_assert_valid() etc. */
USTR_CONF_I_PROTO
size_t ustr_assert_valid_subustr(const struct Ustr *s1, size_t pos, size_t len)
{ return (ustrp__assert_valid_subustr(1, s1, pos, len)); }
USTR_CONF_I_PROTO
int ustrp_assert_valid_subustrp(const struct Ustrp *s1, size_t pos, size_t len)
{ return (ustrp__assert_valid_subustr(1, &s1->s, pos, len)); }

USTR_CONF_I_PROTO char *ustr_wstr(struct Ustr *s1)
{ /* NOTE: Not EI/II so we can call ustr_assert_valid() here. */
  unsigned char *data = s1->data;
  size_t lenn = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1));
  
  USTR_ASSERT_RET(!ustr_ro(s1), 0);
  
  lenn = USTR__LEN_LEN(s1);
  if (ustr_sized(s1))
    lenn *= 2;
  
  return ((char *)(data + 1 + USTR__REF_LEN(s1) + lenn));
}

USTR_CONF_I_PROTO int ustr_owner(const struct Ustr *s1)
{
  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (ustr_ro(s1))    return (USTR_FALSE);
  if (ustr_fixed(s1)) return (USTR_TRUE);

  switch (USTR__REF_LEN(s1))
  {
#if USTR_CONF_HAVE_64bit_SIZE_MAX
    case 8: if (s1->data[8]) return (USTR_FALSE);
            if (s1->data[7]) return (USTR_FALSE);
            if (s1->data[6]) return (USTR_FALSE);
            if (s1->data[5]) return (USTR_FALSE);
#endif
    case 4: if (s1->data[4]) return (USTR_FALSE);
            if (s1->data[3]) return (USTR_FALSE);
    case 2: if (s1->data[2]) return (USTR_FALSE);
      
    case 1:                  return (s1->data[1] == 1);
      
    case 0:
      
      USTR_ASSERT_NO_SWITCH_DEF("Ref. length bad for ustr__ref_owner()");
  }
  
  return (USTR_TRUE);  /* Ustr with no ref. count */
}

USTR_CONF_I_PROTO int ustr_setf_enomem_err(struct Ustr *s1)
{
  USTR_ASSERT(ustr_assert_valid(s1));

  errno = USTR__ENOMEM;
  if (!ustr_owner(s1))
    return (USTR_FALSE);
  
  s1->data[0] |=  USTR__BIT_ENOMEM;
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_setf_enomem_clr(struct Ustr *s1)
{
  USTR_ASSERT(ustr_assert_valid(s1));
  
  errno = 0;
  if (!ustr_owner(s1))
    return (USTR_FALSE);
  
  s1->data[0] &= ~USTR__BIT_ENOMEM;
  return (USTR_TRUE);
}

USTR_CONF_i_PROTO void ustr__embed_val_set(unsigned char *data,
                                           size_t len, size_t val)
{
  switch (len)
  {
#if USTR_CONF_HAVE_64bit_SIZE_MAX
    case 8:
      data[7] = (val >> 56) & 0xFF;
      data[6] = (val >> 48) & 0xFF;
      data[5] = (val >> 40) & 0xFF;
      data[4] = (val >> 32) & 0xFF;
#endif
    case 4:
      data[3] = (val >> 24) & 0xFF;
      data[2] = (val >> 16) & 0xFF;
    case 2:
      data[1] = (val >>  8) & 0xFF;
    case 1:
      data[0] = (val >>  0) & 0xFF;

      USTR_ASSERT_NO_SWITCH_DEF("Val. length bad for ustr__embed_val_set()");
  }
}

/* no warn here, because most callers already know it's not going to fail */
USTR_CONF_i_PROTO int ustr__ref_set(struct Ustr *s1, size_t ref)
{
  size_t len = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1));
  USTR_ASSERT(ustr_alloc(s1));

  if (!(len = USTR__REF_LEN(s1)))
    return (USTR_FALSE);
  
  ustr__embed_val_set(s1->data + 1, len, ref);
  
  USTR_ASSERT(ustr_assert_valid(s1));

  return (USTR_TRUE);
}

USTR_CONF_I_PROTO int ustr_setf_share(struct Ustr *s1)
{
  USTR_ASSERT(ustr_assert_valid(s1));

  if (!ustr_alloc(s1))
    return (USTR_TRUE);
  
  if (!ustr__ref_set(s1, 0))
    return (USTR_FALSE);
  
  USTR_ASSERT(ustr_assert_valid(s1));
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_setf_owner(struct Ustr *s1)
{
  USTR_ASSERT(ustr_assert_valid(s1));

  if (!ustr_alloc(s1))
    return (USTR_FALSE);

  ustr__ref_set(s1, 1); /* 0 means it's unsharable and so they are the owner */
  
  USTR_ASSERT(ustr_assert_valid(s1));
  return (USTR_TRUE);
}

USTR_CONF_i_PROTO void ustr__len_set(struct Ustr *s1, size_t len)
{ /* can only validate after the right len is in place */
  unsigned char *data = s1->data;
  
  USTR_ASSERT(!ustr_ro(s1));
  ustr__embed_val_set(data + 1 + USTR__REF_LEN(s1), USTR__LEN_LEN(s1), len);
  USTR_ASSERT(ustr_assert_valid(s1));
}

USTR_CONF_i_PROTO void ustr__sz_set(struct Ustr *s1, size_t sz)
{ /* can't validate as this is called before anything is setup */
  size_t lenn = 0;
  
  USTR_ASSERT(!ustr_ro(s1));
  USTR_ASSERT(ustr_sized(s1));

  lenn = USTR__LEN_LEN(s1);
  
  ustr__embed_val_set(s1->data + 1 + USTR__REF_LEN(s1) + lenn, lenn, sz);
}

USTR_CONF_i_PROTO int ustr__ref_add(struct Ustr *s1)
{
  size_t ref = 0;
  size_t lim = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (ustr_ro(s1))
    return (USTR_TRUE);
  if (ustr_fixed(s1))
    return (USTR_FALSE);
  
  switch (USTR__REF_LEN(s1))
  {
#if USTR_CONF_HAVE_64bit_SIZE_MAX
    case 8: if (!lim) lim = 0xFFFFFFFFFFFFFFFFULL;
#endif
    case 4: if (!lim) lim = 0xFFFFFFFFUL;
    case 2: if (!lim) lim = 0xFFFF;
    case 1: if (!lim) lim = 0xFF;
      
      ref = ustr_xi__ref_get(s1);
      if (ref == 0)
        return (USTR_TRUE);
      if (ref == lim)
        return (USTR_FALSE);
      ustr__ref_set(s1, ref + 1);
      return (USTR_TRUE);
  
    case 0: /* Ustr with no reference count */
      
      USTR_ASSERT_NO_SWITCH_DEF("Ref. length bad for ustr__ref_add()");
  }

  return (USTR_FALSE);
}

USTR_CONF_i_PROTO size_t ustr__ref_del(struct Ustr *s1)
{
  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (!ustr_alloc(s1))
    return (-1);

  switch (USTR__REF_LEN(s1))
  {
    case 8:
    case 4:
    case 2:
    case 1:
    {
      size_t ref = ustr_xi__ref_get(s1);
      
      if (ref == 0)
        return (-1);
      if (ref == 1) /* Special case this so it doesn't "go shared"
                     * plus this is a common case and doing this is
                     * marginally faster */
        return (0);
      
      ustr__ref_set(s1, ref - 1);
      return (ref - 1);
    }
          
    case 0: /* Ustr with no reference count */

      USTR_ASSERT_NO_SWITCH_DEF("Ref. length bad for ustr__ref_del()");
  }

  return (0);
}

USTR_CONF_I_PROTO size_t ustr_size_overhead(const struct Ustr *s1)
{
  size_t lenn = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1));

  if (!s1->data[0])
    return (1);

  lenn = USTR__LEN_LEN(s1);
  if (ustr_sized(s1))
    lenn *= 2;
  
  return (1 + USTR__REF_LEN(s1) + lenn + sizeof(USTR_END_ALOCDx));
}

USTR_CONF_I_PROTO size_t ustr_size_alloc(const struct Ustr *s1)
{ /* copy and paste so that ustr_ro() does the right thing */
  size_t oh = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (ustr_sized(s1))
    return (ustr__sz_get(s1));

  oh = ustr_size_overhead(s1);
  USTR_ASSERT((oh + ustr_len(s1)) >= oh);
  
  if (ustr_exact(s1))
    return (ustr_len(s1) + oh);

  return (ustr__ns(ustr_len(s1) + oh));
}

USTR_CONF_i_PROTO void ustrp__free(struct Ustr_pool *p, struct Ustr *s1)
{
  if (!s1) return;

  USTR_ASSERT(ustrp__assert_valid(!!p, s1));
    
  if (!ustr__ref_del(s1))
  {
    if (p)
      p->pool_sys_free(p, s1);
    else
      USTR_CONF_FREE(s1);
  }
}

USTR_CONF_I_PROTO void ustr_free(struct Ustr *s1)
{ return (ustrp__free(0, s1)); }
USTR_CONF_I_PROTO void ustrp_free(struct Ustr_pool *p, struct Ustrp *s1)
{ return (ustrp__free(p, &s1->s)); }

/* shortcut -- needs to be here, as lots of things calls this */
USTR_CONF_i_PROTO
void ustrp__sc_free2(struct Ustr_pool *p, struct Ustr **ps1, struct Ustr *s2)
{
  USTR_ASSERT(ps1);
  USTR_ASSERT(ustrp__assert_valid(!!p, s2)); /* don't pass NULL */
  
  ustrp__free(p, *ps1);
  *ps1 = s2;
}

USTR_CONF_i_PROTO size_t ustr__ns(size_t num)
{
  size_t min_sz = 4;
  
  if (num > ((USTR__SIZE_MAX / 4) * 3))
    return (USTR__SIZE_MAX);

  /* *2 is too much, we end up wasting a lot of RAM. So we do *1.5. */
  while (min_sz < num)
  {
    size_t adder = min_sz / 2;

    min_sz += adder;
    if (min_sz >= num) break;
    min_sz += adder;
  }
      
  return (min_sz);
}

/* ---------------- init - helpers so others can make Ustr's ---------------- */
USTR_CONF_I_PROTO size_t ustr_init_size(size_t sz, size_t rbytes, int exact,
                                        size_t len)
{
  size_t oh  = 0;
  size_t rsz = sz ? sz : len;
  size_t lbytes = 0;
  
  USTR_ASSERT_RET((rbytes == 0) ||
                  (rbytes == 1) || (rbytes == 2) || (rbytes == 4) ||
                  (USTR_CONF_HAVE_64bit_SIZE_MAX && (rbytes == 8)), 0);

  do
  {
    size_t sbytes = 0;

    lbytes = ustr__nb(rsz);
    if (!sz && ((lbytes == 8) || (rbytes == 8)))
      sz = 1;
    
    USTR_ASSERT(    (lbytes == 1) || (lbytes == 2) || (lbytes == 4) ||
                    (USTR_CONF_HAVE_64bit_SIZE_MAX && (lbytes == 8)));
  
    if (sz)
    {
      if (rbytes <= 1)
        rbytes = 2;
      if (lbytes <= 1)
        lbytes = 2;
      sbytes = lbytes;
    }
    
    oh = 1 + rbytes + lbytes + sbytes + sizeof(USTR_END_ALOCDx);
    rsz = oh + len;
  
    if (rsz < len)
    {
      errno = USTR__EINVAL;
      return (0);
    }

    USTR_ASSERT((lbytes <= ustr__nb(rsz)) ||
                ((lbytes == 2) && sz && (ustr__nb(rsz) == 1)));
  } while (lbytes < ustr__nb(rsz));
  
  if (exact)
    return (rsz);
  
  return (ustr__ns(rsz));
}

/* NIL terminate -- with possible end marker */
USTR_CONF_i_PROTO void ustr__terminate(unsigned char *ptr, int alloc,size_t len)
{
  if (sizeof(USTR_END_ALOCDx) == 1)
    ptr[len] = 0;
  else if (alloc)
    memcpy(ptr + len, USTR_END_ALOCDx, sizeof(USTR_END_ALOCDx));
  else
    memcpy(ptr + len, USTR_END_FIXEDx, sizeof(USTR_END_FIXEDx));
}

USTR_CONF_I_PROTO
struct Ustr *ustr_init_alloc(void *data, size_t rsz, size_t sz,
                             size_t rbytes, int exact, int emem, size_t len)
{
  static const unsigned char map_big_pow2[9] = {-1, -1, 0, -1, 1, -1, -1, -1,2};
  static const unsigned char map_pow2[5] = {0, 1, 2, -1, 3};
  struct Ustr *ret = data;
  int nexact = !exact;
  int sized  = 0;
  size_t lbytes = 0;
  size_t sbytes = 0;
  size_t oh = 0;
  const size_t eos_len = sizeof(USTR_END_ALOCDx);
  
  USTR_ASSERT_RET((rbytes == 0) ||
                  (rbytes == 1) || (rbytes == 2) || (rbytes == 4) ||
                  (USTR_CONF_HAVE_64bit_SIZE_MAX && (rbytes == 8)), USTR_NULL);
  USTR_ASSERT(data);
  USTR_ASSERT(exact == !!exact);
  USTR_ASSERT(emem  == !!emem);
  USTR_ASSERT(!sz || (sz == rsz));
  USTR_ASSERT_RET(!sz || (sz > len), USTR_NULL);

  if (!sz && (rbytes == 8))
    sz = rsz; /* whee... */
  
  lbytes = ustr__nb(sz ? sz : len);
  if (!sz && (lbytes == 8))
    sz = rsz; /* whee... */
  USTR_ASSERT(lbytes == ustr__nb(sz ? sz : len));
  
  USTR_ASSERT(    (lbytes == 1) || (lbytes == 2) || (lbytes == 4) ||
                  (USTR_CONF_HAVE_64bit_SIZE_MAX && (lbytes == 8)));
  
  if (sz)
  {
    if (sz < (1 + 2 + 2 + 1))
      goto val_inval;
    
    if (rbytes <= 1)
      rbytes = 2;
    if (lbytes <= 1)
      lbytes = 2;
    sbytes = lbytes;
  }
  oh = 1 + rbytes + lbytes + sbytes + eos_len;

  if (rsz < (oh + len))
    goto val_inval;
  
  if (sz)     sized  = USTR__BIT_HAS_SZ;
  if (nexact) nexact = USTR__BIT_NEXACT;
  if (emem)   emem   = USTR__BIT_ENOMEM;
    
  ret->data[0]  = USTR__BIT_ALLOCD | sized | nexact | emem;
  if (sz)
    ret->data[0] |= (map_big_pow2[rbytes] << 2) | map_big_pow2[lbytes];
  else
    ret->data[0] |= (map_pow2[rbytes] << 2) | map_pow2[lbytes];

  ustr__terminate(ret->data, USTR_TRUE, (oh - eos_len) + len);

  if (sz)
    ustr__sz_set(ret, sz);
  ustr__len_set(ret, len);
  ustr__ref_set(ret,   1);

  USTR_ASSERT(ustr_assert_valid(ret));
  USTR_ASSERT( ustr_alloc(ret));
  USTR_ASSERT(!ustr_fixed(ret));
  USTR_ASSERT(!ustr_ro(ret));
  USTR_ASSERT( ustr_enomem(ret) == !!emem);
  USTR_ASSERT( ustr_exact(ret)  == exact);
  USTR_ASSERT(!ustr_shared(ret));
  USTR_ASSERT( ustr_owner(ret));

  return (ret);

 val_inval:
  errno = USTR__EINVAL;
  return (USTR_NULL);
}
USTR_CONF_I_PROTO
struct Ustrp *ustrp_init_alloc(void *data, size_t rsz, size_t sz,
                               size_t rbytes, int exact, int emem, size_t len)
{ return (USTRP(ustr_init_alloc(data, rsz, sz, rbytes, exact, emem, len))); }

USTR_CONF_I_PROTO
struct Ustr *ustr_init_fixed(void *data, size_t sz, int exact, size_t len)
{
  struct Ustr *ret = data;
  void *tmp = 0; /* move type between char and unsigned char */
  size_t rbytes = 0;
  const int    emem   = USTR_FALSE;
  
  USTR_ASSERT(sz);
  
  if (!ustr_init_alloc(data, sz, sz, rbytes, exact, emem, len))
    return (USTR_NULL);

  tmp = ustr_wstr(ret); /* done here,
                           as it might not be valid until we terminate */

  ret->data[0] &= ~USTR__BIT_ALLOCD;
  ustr__terminate(tmp, USTR_FALSE, len);
  if ((rbytes = USTR__REF_LEN(ret))) /* _large_ */
    ustr__embed_val_set(ret->data + 1, rbytes, 0);

  USTR_ASSERT(ustr_assert_valid(ret));
  USTR_ASSERT( ustr_fixed(ret));
  USTR_ASSERT(!ustr_alloc(ret));
  USTR_ASSERT(!ustr_ro(ret));
  USTR_ASSERT( ustr_enomem(ret) == emem);
  USTR_ASSERT(!ustr_shared(ret));
  USTR_ASSERT( ustr_owner(ret));

  return (ret);
}
USTR_CONF_I_PROTO
struct Ustrp *ustrp_init_fixed(void *data, size_t sz, int exact, size_t len)
{ return (USTRP(ustr_init_fixed(data, sz, exact, len))); }

USTR_CONF_I_PROTO size_t ustr_size(const struct Ustr *s1)
{ /* size of available space in the string */
  size_t oh = 0;

  USTR_ASSERT(ustr_assert_valid(s1));
  
  if (ustr_sized(s1))
    return (ustr__sz_get(s1) - ustr_size_overhead(s1));
  if (ustr_exact(s1))
    return (ustr_len(s1));

  oh = ustr_size_overhead(s1);
  return (ustr__ns(ustr_len(s1) + oh) - oh);
}

/* ---------------- allocations ---------------- */
/* NOTE: This is one of the two main "allocation" functions --
 * this is the only thing that calls MALLOC. */
USTR_CONF_i_PROTO
struct Ustr *ustrp__dupx_undef(struct Ustr_pool *p, size_t sz, size_t rbytes, 
                               int exact, int emem, size_t len)
{
  struct Ustr *ret = USTR_NULL;
  struct Ustr *chk = USTR_NULL;
  size_t rsz = 0;
  
  USTR_ASSERT((rbytes == 0) || (rbytes == 1) || (rbytes == 2) || (rbytes == 4)||
              (USTR_CONF_HAVE_64bit_SIZE_MAX && (rbytes == 8)));
  USTR_ASSERT(exact == !!exact);
  USTR_ASSERT(emem  == !!emem);

  if (!len && ustr__dupx_cmp_eq(sz, rbytes, exact, emem, USTR__DUPX_DEF))
    return (USTR("")); /* We don't go to all the trouble ustr_del() does.
                        * Which is probably better overall. */
  
  if (!(rsz = ustr_init_size(sz, rbytes, exact, len)))
    return (USTR_NULL);

  if (p)
    ret = p->pool_sys_malloc(p, rsz);
  else
    ret = USTR_CONF_MALLOC(rsz);
  
  if (!ret)
  {
    errno = USTR__ENOMEM;
    return (USTR_NULL);
  }
  
  chk = ustr_init_alloc(ret, rsz, sz ? rsz : 0, rbytes, exact, emem, len);
  USTR_ASSERT(chk);
  
  USTR_ASSERT(ustrp__assert_valid(!!p, ret));
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__rw_realloc(struct Ustr_pool *p, struct Ustr **ps1,
                      int sized, size_t osz, size_t nsz)
{
  struct Ustr *ret = USTR_NULL;
  
  USTR_ASSERT(ustr_alloc(*ps1));
  USTR_ASSERT(osz == ustr_size_alloc(*ps1));
  USTR_ASSERT(sized == !!sized);
  USTR_ASSERT(sized == ustr_sized(*ps1));
  ustr_assert(USTR__ASSERT_MALLOC_CHECK_MEM(p, *ps1));

  /*  printf("1. p=%p, osz=%zu, nsz=%zu\n", p, osz, nsz); */
  if (p)
    ret = p->pool_sys_realloc(p, *ps1, osz, nsz);
  else
    ret = USTR_CONF_REALLOC(*ps1, nsz);
  
  if (!ret)
  {
    ustr_setf_enomem_err(*ps1);
    return (USTR_FALSE);
  }
  if (sized)
    ustr__sz_set(ret, nsz);

  *ps1 = ret;

  return (USTR_TRUE);
}

USTR_CONF_i_PROTO void ustr__memcpy(struct Ustr *s1, size_t off,
                                    const void *ptr, size_t len)
{ /* can't call ustr_wstr() if len == 0, as it might be RO */
  if (!len)
    return;
  memcpy(ustr_wstr(s1) + off, ptr, len);
}

USTR_CONF_i_PROTO void ustr__memset(struct Ustr *s1, size_t off,
                                    int chr, size_t len)
{ /* can't call ustr_wstr() if len == 0, as it might be RO */
  if (!len)
    return;
  memset(ustr_wstr(s1) + off, chr, len);
}

/* ---------------- del ---------------- */

/* Fine grained management of the space allocated to a sized Ustr */
USTR_CONF_i_PROTO
int ustrp__realloc(struct Ustr_pool *p, struct Ustr **ps1, size_t nsz)
{
  struct Ustr *s1 = USTR_NULL;
  size_t oh  = 0;
  size_t len = 0;
  size_t msz = 0; /* min size */
  size_t osz = 0; /* old size */
  int    ret = USTR_TRUE;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  s1 = *ps1;
  if (!ustr_sized(s1) || !ustr_alloc(s1) || !ustr_owner(s1))
    return (USTR_FALSE);

  oh  = ustr_size_overhead(s1);
  len = ustr_len(s1);
  msz = oh + len;
  
  if (!nsz)
    nsz = len;
  nsz += oh; /* if this overflows, we'll get it at the msz test */
  
  osz = ustr__sz_get(s1);
  if (nsz == osz) /* if there's nothing to do... */
    return (USTR_TRUE);

  if (nsz < msz) /* we can't go less than the minimum */
    return (USTR_FALSE);
  
  /* Don't let the length num. bytes go up, as we might as well just dupx()
   */
  if (ustr__nb(nsz) > USTR__LEN_LEN(s1))
    return (USTR_FALSE);
  
  ret = ustrp__rw_realloc(p, ps1, USTR_TRUE, osz, nsz);
  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));

  return (ret);
}
USTR_CONF_I_PROTO int ustr_realloc(struct Ustr **ps1, size_t sz)
{ return (ustrp__realloc(0, ps1, sz)); }
USTR_CONF_I_PROTO int ustrp_realloc(struct Ustr_pool *p,
                                    struct Ustrp **ps1, size_t sz)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__realloc(p, &tmp, sz);
  *ps1 = USTRP(tmp);
  return (ret);
}

/* Can we actually RW to this Ustr, at _this_ moment, _this_ len */
USTR_CONF_i_PROTO
int ustr__rw_mod(struct Ustr *s1, size_t nlen, size_t *sz, size_t *oh,
                 size_t *osz, size_t *nsz, int *alloc)
{
  size_t lbytes = 0;
  size_t sbytes = 0;

  if (!ustr_owner(s1))
    return (USTR_FALSE);

  *sz = 0;
  if (ustr_sized(s1))
    *sz = ustr__sz_get(s1);
  *osz = *sz;
  
  lbytes = USTR__LEN_LEN(s1);
  if (*sz)
    sbytes = lbytes;
  USTR_ASSERT(!*sz || (ustr__nb(*sz) == lbytes) ||
              ((ustr__nb(*sz) == 1) && (lbytes == 2))); /* 2 is the minimum */
  
  if (ustr__nb(nlen) > lbytes)
    return (USTR_FALSE); /* in theory we could do better, but it's _hard_ */
  
  *oh  = 1 + USTR__REF_LEN(s1) + lbytes + sbytes + sizeof(USTR_END_ALOCDx);
  *nsz = *oh + nlen;

  if (*nsz < nlen)
    return (USTR_FALSE);
  if (*nsz > USTR__SIZE_MAX) /* 32bit overflow on 64bit size_t */
    return (USTR_FALSE);

  *alloc = USTR_FALSE; /* don't need to allocate/deallocate anything */
  if (*nsz <= *sz)
    return (USTR_TRUE); /* ustr_sized() */
  
  if (!ustr_exact(s1))
    *nsz = ustr__ns(*nsz);
  
  *osz = ustr_size_alloc(s1);
  
  if (!*sz && (*nsz == *osz))
    return (USTR_TRUE);
  
  *alloc = ustr_alloc(s1); /* _do_   need to deallocate */
  if (!*sz && (*nsz <= *osz))
    return (USTR_TRUE);
  
  if (!*alloc)
    return (USTR_FALSE);

  return (USTR_TRUE);
}

/* NOTE: This is the main "deallocation" function (apart from plain free) --
 * this is one of only three things that removes data via. REALLOC.
 * Others are in ustr-set.h */
USTR_CONF_i_PROTO
int ustrp__del(struct Ustr_pool *p, struct Ustr **ps1, size_t len)
{
  struct Ustr *s1  = USTR_NULL;
  struct Ustr *ret = USTR_NULL;
  size_t sz  = 0;
  size_t oh  = 0;
  size_t osz = 0;
  size_t nsz = 0;
  size_t clen = 0;
  size_t nlen = 0;
  int alloc = USTR_FALSE;

  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  
  if (!len)
    return (USTR_TRUE);

  s1   = *ps1;
  clen = ustr_len(s1);
  /* under certain conditions, we can just return "" as it's much more efficient
   * and we don't get anything with not doing it. */
  if (!(nlen = clen - len) && /* we are deleting everything */
      !(ustr_fixed(*ps1) ||   /* NOT in "free" space, or */
        (ustr_sized(*ps1) && ustr_owner(*ps1))) &&    /* sized with one ref. */
      ustr__dupx_cmp_eq(USTR__DUPX_DEF, USTR__DUPX_FROM(s1))) /* def. config. */
  {
    ustrp__sc_free2(p, ps1, USTR(""));
    return (USTR_TRUE);
  }
  
  if (nlen > clen) /* underflow */
    return (USTR_FALSE);

  if (ustr__rw_mod(s1, nlen, &sz, &oh, &osz, &nsz, &alloc))
  {
    size_t eos_len = sizeof(USTR_END_ALOCDx);
    
    if (alloc)
    { /* ignore errors? -- can they happen on truncate? */
      int emem = ustr_enomem(*ps1);

      USTR_ASSERT(nsz < osz);
      USTR_ASSERT(!sz);
      
      if (!ustrp__rw_realloc(p, ps1, USTR_FALSE, osz, nsz))
      {
        if (!p)
        {
          ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(*ps1, osz));
          USTR__CNTL_MALLOC_CHECK_FIXUP_REALLOC(*ps1, nsz);
          ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(*ps1, nsz));
        }
        
        if (!emem)
          ustr_setf_enomem_clr(*ps1);
      }
    }
      
    ustr__terminate((*ps1)->data, ustr_alloc(*ps1), (oh - eos_len) + nlen);
    ustr__len_set(*ps1, nlen);
    
    USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
    return (USTR_TRUE);
  }

  USTR_ASSERT(!ustr_limited(s1));
  
  if (!(ret = ustrp__dupx_undef(p, USTR__DUPX_FROM(s1), nlen)))
  {
    ustr_setf_enomem_err(s1);
    return (USTR_FALSE);
  }

  ustr__memcpy(ret, 0, ustr_cstr(s1), nlen);
  ustrp__sc_free2(p, ps1, ret);

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_del(struct Ustr **ps1, size_t len)
{ return (ustrp__del(0, ps1, len)); }
USTR_CONF_I_PROTO
int ustrp_del(struct Ustr_pool *p, struct Ustrp **ps1, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__del(p, &tmp, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__del_subustr(struct Ustr_pool *p,
                       struct Ustr **ps1, size_t pos, size_t len)
{
  struct Ustr *s1  = USTR_NULL;
  struct Ustr *ret = USTR_NULL;
  size_t sz  = 0;
  size_t oh  = 0;
  size_t osz = 0;
  size_t nsz = 0;
  size_t clen = 0;
  size_t nlen = 0;
  int alloc = USTR_FALSE;
  const char *ocstr = 0;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  if (!len)
    return (USTR_TRUE);

  s1   = *ps1;
  clen = ustrp__assert_valid_subustr(!!p, s1, pos, len);
  if (!clen)
    return (USTR_FALSE);
  if (--pos == (clen - len)) /* deleting from the end */
    return (ustrp__del(p, ps1, len));

  nlen = clen - len;
  USTR_ASSERT(nlen < clen);
  
  if (ustr__rw_mod(s1, nlen, &sz, &oh, &osz, &nsz, &alloc))
  { /* Move everything to the begining and call ustr_del() */
    char *ptr = ustr_wstr(s1);
    
    USTR_ASSERT(nlen - pos);

    memmove(ptr + pos, ptr + pos + len, (nlen - pos));

    return (ustrp__del(p, ps1, len));
  }

  USTR_ASSERT(!ustr_limited(s1));
  
  /* Can't do anything sane, give up and build a new string from scratch */
  if (!(ret = ustrp__dupx_undef(p, USTR__DUPX_FROM(s1), nlen)))
  {
    ustr_setf_enomem_err(s1);
    return (USTR_FALSE);
  }

  ocstr = ustr_cstr(s1);

  USTR_ASSERT(pos || (nlen - pos)); /* can be both */
  
  ustr__memcpy(ret, 0,   ocstr,                    pos);
  ustr__memcpy(ret, pos, ocstr + pos + len, nlen - pos);

  ustrp__sc_free2(p, ps1, ret);

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_del_subustr(struct Ustr **ps1, size_t pos,size_t len)
{ return (ustrp__del_subustr(0, ps1, pos, len)); }
USTR_CONF_I_PROTO
int ustrp_del_subustrp(struct Ustr_pool *p,
                       struct Ustrp **ps1, size_t pos, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__del_subustr(p, &tmp, pos, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

/* ---------------- dupx/dup ---------------- */

USTR_CONF_I_PROTO struct Ustr *ustr_dupx_undef(size_t sz, size_t rbytes, 
                                               int exact, int emem, size_t len)
{ return (ustrp__dupx_undef(0, sz, rbytes, exact, emem, len)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dupx_undef(struct Ustr_pool *p, size_t sz, size_t rbytes, 
                               int exact, int emem, size_t len)
{ return (USTRP(ustrp__dupx_undef(p, sz, rbytes, exact, emem, len))); }

USTR_CONF_I_PROTO struct Ustr *ustr_dup_undef(size_t len)
{ return (ustr_dupx_undef(USTR__DUPX_DEF, len)); }

USTR_CONF_I_PROTO struct Ustrp *ustrp_dup_undef(struct Ustr_pool *p, size_t len)
{ return (ustrp_dupx_undef(p, USTR__DUPX_DEF, len)); }

USTR_CONF_i_PROTO
struct Ustr *ustrp__dupx_empty(struct Ustr_pool *p, size_t sz, size_t rbytes, 
                               int exact, int emem)
{ /* set the error bit, so we always get malloc()'d data, then clear it */
  struct Ustr *s1 = ustrp__dupx_undef(p, sz, rbytes, exact, USTR_TRUE, 0);
  int eret = USTR_FALSE;

  if (!s1 || emem)
    return (s1);

  eret = ustr_setf_enomem_clr(s1);
  USTR_ASSERT(eret);
  
  return (s1);
}
USTR_CONF_I_PROTO struct Ustr *ustr_dupx_empty(size_t sz, size_t rbytes, 
                                               int exact, int emem)
{ return (ustrp__dupx_empty(0, sz, rbytes, exact, emem)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dupx_empty(struct Ustr_pool *p, size_t sz, size_t rbytes,
                               int exact, int emem)
{ return (USTRP(ustrp__dupx_empty(p, sz, rbytes, exact, emem))); }

USTR_CONF_I_PROTO struct Ustr *ustr_dup_empty(void)
{ return (ustr_dupx_empty(USTR__DUPX_DEF)); }

USTR_CONF_I_PROTO struct Ustrp *ustrp_dup_empty(struct Ustr_pool *p)
{ return (ustrp_dupx_empty(p, USTR__DUPX_DEF)); }

USTR_CONF_i_PROTO
struct Ustr *ustrp__dupx_buf(struct Ustr_pool *p, size_t sz, size_t rbytes,
                             int exact, int emem, const void *data, size_t len)
{
  struct Ustr *s1 = ustrp__dupx_undef(p, sz, rbytes, exact, emem, len);

  if (!s1)
    return (USTR_NULL);

  ustr__memcpy(s1, 0, data, len);

  USTR_ASSERT(ustrp__assert_valid(!!p, s1));
  return (s1);
}
USTR_CONF_I_PROTO
struct Ustr *ustr_dupx_buf(size_t sz, size_t rb, int exact,
                           int emem, const void *data, size_t len)
{ return (ustrp__dupx_buf(0, sz, rb, exact, emem, data, len)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dupx_buf(struct Ustr_pool *p, size_t sz, size_t rb,
                             int exact, int emem, const void *data, size_t len)
{ return (USTRP(ustrp__dupx_buf(p, sz, rb, exact, emem, data, len))); }

USTR_CONF_I_PROTO struct Ustr *ustr_dup_buf(const void *data, size_t len)
{ return (ustr_dupx_buf(USTR__DUPX_DEF, data, len)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dup_buf(struct Ustr_pool *p, const void *data, size_t len)
{ return (USTRP(ustrp_dupx_buf(p, USTR__DUPX_DEF, data, len))); }

USTR_CONF_i_PROTO
struct Ustr *ustrp__dup(struct Ustr_pool *p, const struct Ustr *s1)
{ /* This ignores the const argument, because it doesn't alter the data, or at
   * all when ustr_ro(). */
  ustr_assert(USTR__ASSERT_MALLOC_CHECK_MEM(p, s1));
  
  if (ustr__ref_add((struct Ustr *)s1))
    return ((struct Ustr *)s1);

  return (ustrp__dupx_buf(p, USTR__DUPX_FROM(s1), ustr_cstr(s1), ustr_len(s1)));
}
USTR_CONF_I_PROTO struct Ustr *ustr_dup(const struct Ustr *s1)
{ return (ustrp__dup(0, s1)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dup(struct Ustr_pool *p, const struct Ustrp *s1)
{ return (USTRP(ustrp__dup(p, &s1->s))); }

USTR_CONF_i_PROTO
struct Ustr *ustrp__dupx(struct Ustr_pool *p, size_t sz, size_t rbytes,
                         int exact, int emem, const struct Ustr *s1)
{ /* the exactneustr of the options is more important than the reference */
  USTR_ASSERT((rbytes == 0) || (rbytes == 1) || (rbytes == 2) || (rbytes == 4)||
              (USTR_CONF_HAVE_64bit_SIZE_MAX && (rbytes == 8)));
  USTR_ASSERT(exact == !!exact);
  USTR_ASSERT(emem  == !!emem);
  
  if (ustr__dupx_cmp_eq(sz, rbytes, exact, emem, USTR__DUPX_FROM(s1)))
    return (ustrp__dup(p, s1));
  
  return (ustrp__dupx_buf(p, sz,rbytes,exact,emem, ustr_cstr(s1),ustr_len(s1)));
}
USTR_CONF_I_PROTO struct Ustr *ustr_dupx(size_t sz, size_t rbytes, int exact,
                                         int emem, const struct Ustr *s1)
{ return (ustrp__dupx(0, sz, rbytes, exact, emem, s1)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dupx(struct Ustr_pool *p, size_t sz, size_t rbytes,
                         int exact, int emem, const struct Ustrp *s1)
{ return (USTRP(ustrp__dupx(p, sz, rbytes, exact, emem, &s1->s))); }

USTR_CONF_i_PROTO
struct Ustr *ustrp__dupx_subustr(struct Ustr_pool *p,
                                 size_t sz, size_t rbytes, int exact, int emem,
                                 const struct Ustr *s2, size_t pos, size_t len)
{
  size_t clen = 0;
  
  USTR_ASSERT(ustrp__assert_valid(!!p, s2));
  USTR_ASSERT(pos);

  if (!len)
    return (ustrp__dupx_undef(p, sz, rbytes, exact, emem, len));
  
  clen = ustrp__assert_valid_subustr(!!p, s2, pos, len);
  if (!clen)
    return (USTR_NULL);
  if (len == clen)
    return (ustrp__dupx(p, sz, rbytes, exact, emem, s2));
  
  return (ustrp__dupx_buf(p,sz,rbytes,exact,emem, ustr_cstr(s2) + --pos, len));
}
USTR_CONF_I_PROTO
struct Ustr *ustr_dupx_subustr(size_t sz, size_t rbytes, int exact, int emem,
                               const struct Ustr *s2, size_t pos, size_t len)
{ return (ustrp__dupx_subustr(0, sz, rbytes, exact, emem, s2, pos, len)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dupx_subustrp(struct Ustr_pool *p,
                                  size_t sz, size_t rbytes, int exact, int emem,
                                  const struct Ustrp *s2, size_t pos,size_t len)
{ return (USTRP(ustrp__dupx_subustr(p, sz, rbytes, exact, emem,
                                    &s2->s, pos, len))); }

USTR_CONF_i_PROTO
struct Ustr *ustrp__dup_subustr(struct Ustr_pool *p, const struct Ustr *s2,
                                size_t pos, size_t len)
{ return (ustrp__dupx_subustr(p, USTR__DUPX_FROM(s2), s2, pos, len)); }
USTR_CONF_I_PROTO struct Ustr *ustr_dup_subustr(const struct Ustr *s2,
                                                size_t pos, size_t len)
{ return (ustrp__dup_subustr(0, s2, pos, len)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dup_subustrp(struct Ustr_pool *p, const struct Ustrp *s2,
                                 size_t pos, size_t len)
{ return (USTRP(ustrp__dup_subustr(p, &s2->s, pos, len))); }

USTR_CONF_i_PROTO
struct Ustr *ustrp__dupx_rep_chr(struct Ustr_pool *p,
                                 size_t sz, size_t rbytes, int exact, int emem,
                                 char chr, size_t len)
{
  struct Ustr *s1 = ustrp__dupx_undef(p, sz, rbytes, exact, emem, len);
  
  if (!s1)
    return (USTR_NULL);

  if (len)
    ustr__memset(s1, 0, chr, len);

  USTR_ASSERT(ustrp__assert_valid(!!p, s1));
  return (s1);
}
USTR_CONF_I_PROTO
struct Ustr *ustr_dupx_rep_chr(size_t sz, size_t rbytes, int exact, int emem,
                               char chr, size_t len)
{ return (ustrp__dupx_rep_chr(0, sz, rbytes, exact, emem, chr, len)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dupx_rep_chr(struct Ustr_pool *p,
                                 size_t sz, size_t rbytes, int exact, int emem,
                                 char chr, size_t len)
{ return (USTRP(ustrp__dupx_rep_chr(p, sz, rbytes, exact, emem, chr, len))); }
USTR_CONF_I_PROTO struct Ustr *ustr_dup_rep_chr(char chr, size_t len)
{ return (ustr_dupx_rep_chr(USTR__DUPX_DEF, chr, len)); }
USTR_CONF_I_PROTO
struct Ustrp *ustrp_dup_rep_chr(struct Ustr_pool *p, char chr, size_t len)
{ return (ustrp_dupx_rep_chr(p, USTR__DUPX_DEF, chr, len)); }

/* ---------------- add ---------------- */

/* NOTE: This is one of the two main "allocation" functions --
 * this is one of three things funcs that gets more data via. REALLOC.
 * Others are in ustr-set.h */
USTR_CONF_i_PROTO
int ustrp__add_undef(struct Ustr_pool *p, struct Ustr **ps1, size_t len)
{
  struct Ustr *s1  = USTR_NULL;
  struct Ustr *ret = USTR_NULL;
  size_t clen = 0;
  size_t nlen = 0;
  size_t sz   = 0;
  size_t oh   = 0;
  size_t osz  = 0;
  size_t nsz  = 0;
  int alloc = USTR_FALSE;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  
  if (!len)
    return (USTR_TRUE);

  s1   = *ps1;
  clen = ustr_len(s1);
  if ((nlen = clen + len) < clen) /* overflow */
    goto fail_enomem;

  if (ustr__rw_mod(s1, nlen, &sz, &oh, &osz, &nsz, &alloc))
  {
    size_t eos_len = sizeof(USTR_END_ALOCDx);

    if (alloc && !ustrp__rw_realloc(p, ps1, !!sz, osz, nsz))
      return (USTR_FALSE);
    ustr__terminate((*ps1)->data, ustr_alloc(*ps1), (oh - eos_len) + nlen);
    ustr__len_set(*ps1, nlen);
    
    USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
    return (USTR_TRUE);
  }

  if (ustr_limited(s1))
  {
    ustr_setf_enomem_err(s1);
    return (USTR_FALSE);
  }
  
  if (!(ret = ustrp__dupx_undef(p, USTR__DUPX_FROM(s1), nlen)))
    goto fail_enomem;
  
  ustr__memcpy(ret, 0, ustr_cstr(s1), ustr_len(s1));
  ustrp__sc_free2(p, ps1, ret);

  USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
  return (USTR_TRUE);

 fail_enomem:
  ustr_setf_enomem_err(s1);
  return (USTR_FALSE);
}
USTR_CONF_I_PROTO int ustr_add_undef(struct Ustr **ps1, size_t len)
{ return (ustrp__add_undef(0, ps1, len)); }
USTR_CONF_I_PROTO
int ustrp_add_undef(struct Ustr_pool *p, struct Ustrp **ps1, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__add_undef(p, &tmp, len);
  *ps1 = USTRP(tmp);
  return (ret);  
}

USTR_CONF_i_PROTO int ustrp__add_buf(struct Ustr_pool *p, struct Ustr **ps1,
                                     const void *s2, size_t len)
{
  if (!ustrp__add_undef(p, ps1, len))
    return (USTR_FALSE);

  ustr__memcpy(*ps1, ustr_len(*ps1) - len, s2, len);

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_add_buf(struct Ustr **ps1, const void *s2,size_t len)
{ return (ustrp__add_buf(0, ps1, s2, len)); }
USTR_CONF_I_PROTO int ustrp_add_buf(struct Ustr_pool *p, struct Ustrp **ps1,
                                    const void *s2, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__add_buf(p, &tmp, s2, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

/* If we can use _dup(), otherwise just pretend it's a buf+len */
USTR_CONF_i_PROTO
int ustr__treat_as_buf(const struct Ustr *s1, size_t len1, size_t len2)
{
  USTR_ASSERT(!len1 || (len1 == ustr_len(s1))); /* set() uses 0 */
  USTR_ASSERT((len1 < (len1 + len2)) || !len2); /* no overflow allowed */

  if (len1)
    return (USTR_TRUE);
  
  if (ustr_limited(s1))
    return (USTR_TRUE);

  if (ustr_owner(s1) && (ustr_size(s1) >= len2))
    return (USTR_TRUE);

  return (USTR_FALSE);
}

USTR_CONF_i_PROTO
int ustrp__add(struct Ustr_pool *p, struct Ustr **ps1, const struct Ustr *s2)
{
  struct Ustr *ret = USTR_NULL;
  size_t len1 = 0;
  size_t len2 = 0;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  USTR_ASSERT(ustrp__assert_valid(!!p, s2));

  len1 = ustr_len(*ps1);
  len2 = ustr_len(s2);

  if (len1 > (len1 + len2))
  {
    errno = USTR__ENOMEM;
    return (USTR_FALSE);
  }
  
  if (!len2)
    return (USTR_TRUE);
  
  if ((*ps1 == s2) && ustr_owner(s2) && ustr_alloc(s2))
  { /* only one reference, so we can't take _cstr() before we realloc */
    if (!ustrp__add_undef(p, ps1, len1))
      return (USTR_FALSE);
    
    ustr__memcpy(*ps1, len1, ustr_cstr(*ps1), len1);
    
    USTR_ASSERT(ustrp__assert_valid(!!p, *ps1));
    return (USTR_TRUE);
  }
  
  if (ustr__treat_as_buf(*ps1, len1, len2))
    return (ustrp__add_buf(p, ps1, ustr_cstr(s2), len2));

  USTR_ASSERT(!len1);
    
  if (!(ret = ustrp__dupx(p, USTR__DUPX_FROM(*ps1), s2)))
  {
    ustr_setf_enomem_err(*ps1);
    return (USTR_FALSE);
  }
  
  ustrp__sc_free2(p, ps1, ret);
  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_add(struct Ustr **ps1, const struct Ustr *s2)
{ return (ustrp__add(0, ps1, s2)); }
USTR_CONF_I_PROTO
int ustrp_add(struct Ustr_pool *p, struct Ustrp **ps1, const struct Ustrp *s2)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__add(p, &tmp, &s2->s);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO
int ustrp__add_subustr(struct Ustr_pool *p, struct Ustr **ps1,
                       const struct Ustr *s2, size_t pos, size_t len)
{
  size_t clen = 0;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));
  USTR_ASSERT(ustrp__assert_valid(!!p, s2));
  USTR_ASSERT(pos);

  if (!len)
    return (USTR_TRUE);
  
  clen = ustrp__assert_valid_subustr(!!p, s2, pos, len);
  if (!clen)
    return (USTR_FALSE);
  if (len == clen)
    return (ustrp__add(p, ps1, s2));
  
  if (*ps1 != s2)
    return (ustrp__add_buf(p, ps1, ustr_cstr(s2) + pos - 1, len));

  /* maybe only one reference, so we can't take _cstr() before we realloc */
  if (!ustrp__add_undef(p, ps1, len))
    return (USTR_FALSE);

  ustr__memcpy(*ps1, clen, ustr_cstr(*ps1) + pos - 1, len);

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_add_subustr(struct Ustr **ps1, const struct Ustr *s2,
                                       size_t pos, size_t len)
{ return (ustrp__add_subustr(0, ps1, s2, pos, len)); }
USTR_CONF_I_PROTO
int ustrp_add_subustrp(struct Ustr_pool *p, struct Ustrp **ps1,
                       const struct Ustrp *s2, size_t pos, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__add_subustr(p, &tmp, &s2->s, pos, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO int ustrp__add_rep_chr(struct Ustr_pool *p, struct Ustr **ps1,
                                         char chr, size_t len)
{
  if (!ustrp__add_undef(p, ps1, len))
    return (USTR_FALSE);

  ustr__memset(*ps1, ustr_len(*ps1) - len, chr, len);

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_add_rep_chr(struct Ustr **ps1, char chr, size_t len)
{ return (ustrp__add_rep_chr(0, ps1, chr, len)); }
USTR_CONF_I_PROTO int ustrp_add_rep_chr(struct Ustr_pool *p, struct Ustrp **ps1,
                                        char chr, size_t len)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__add_rep_chr(p, &tmp, chr, len);
  *ps1 = USTRP(tmp);
  return (ret);
}

/* ---------------- shortcut ---------------- */

USTR_CONF_I_PROTO void ustr_sc_free2(struct Ustr **ps1, struct Ustr *s2)
{ ustrp__sc_free2(0, ps1, s2); }
USTR_CONF_I_PROTO void ustrp_sc_free2(struct Ustr_pool *p,
                                      struct Ustrp **ps1, struct Ustrp *s2)
{
  struct Ustr *tmp = &(*ps1)->s;
  ustrp__sc_free2(p, &tmp, &s2->s);
  *ps1 = USTRP(tmp);
}

USTR_CONF_i_PROTO void ustrp__sc_free(struct Ustr_pool *p, struct Ustr **ps1)
{
  USTR_ASSERT(ps1);
  
  ustrp__free(p, *ps1);
  *ps1 = USTR_NULL;
}
USTR_CONF_I_PROTO void ustr_sc_free(struct Ustr **ps1)
{ ustrp__sc_free(0, ps1); }
USTR_CONF_I_PROTO void ustrp_sc_free(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  ustrp__sc_free(p, &tmp);
  *ps1 = USTRP(tmp);
}

USTR_CONF_i_PROTO void ustrp__sc_del(struct Ustr_pool *p, struct Ustr **ps1)
{
  if (!ustrp__del(p, ps1, ustr_len(*ps1)))
    /* Very unlikely, but in this case ignore saving the options/data.
     * We can be a little less efficient etc., but no error handling is nice.
     * Only thing you have to watch for is ustr_enomem() might not "work"
     * after a call to here. */
    ustrp__sc_free2(p, ps1, USTR(""));
  
  USTR_ASSERT(!ustr_len(*ps1));
}
USTR_CONF_I_PROTO void ustr_sc_del(struct Ustr **ps1)
{ ustrp__sc_del(0, ps1); }
USTR_CONF_I_PROTO void ustrp_sc_del(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  ustrp__sc_del(p, &tmp);
  *ps1 = USTRP(tmp);
}

USTR_CONF_I_PROTO
void ustr_conf(const struct Ustr *s1, size_t *ret_esz, size_t *ret_ref,
               int *ret_exact, size_t *ret_lenn, size_t *ret_refc)
{
  size_t esz   = 0;
  size_t ref   = 0;
  int    exact = 0;
  size_t refc  = 0;
  
  USTR_ASSERT(ustr_assert_valid(s1));

  if (!ustr_alloc(s1))
  {
    esz   = USTR_CONF_HAS_SIZE;
    ref   = USTR_CONF_REF_BYTES;
    exact = USTR_CONF_EXACT_BYTES;
  }
  else
  {
    if (ustr_sized(s1))
      esz = ustr__sz_get(s1);
    else
      esz = 0;
    
    ref   = USTR__REF_LEN(s1);
    exact = ustr_exact(s1);
    refc  = !!ref;
  }
  
  USTR_ASSERT(ustr__dupx_cmp_eq(USTR__DUPX_FROM(s1),
                                esz, ref, exact, ustr_enomem(s1)));

  if (ret_esz)   *ret_esz   = esz;
  if (ret_ref)   *ret_ref   = ref;
  if (ret_exact) *ret_exact = exact;

  if (ret_lenn)  *ret_lenn  = USTR__LEN_LEN(s1);
  if (ret_refc)  *ret_refc  = refc ? ustr_xi__ref_get(s1) : 0;
}

USTR_CONF_i_PROTO
int ustrp__sc_ensure_owner(struct Ustr_pool *p, struct Ustr **ps1)
{
  struct Ustr *ret = USTR_NULL;
  size_t clen = 0;
  
  USTR_ASSERT(ps1 && ustrp__assert_valid(!!p, *ps1));

  if (ustr_owner(*ps1))
    return (USTR_TRUE);

  if (!(clen = ustr_len(*ps1))) /* so ustr_enomem() and ustr_wstr() work */
    ret = ustrp__dupx_empty(p, USTR__DUPX_FROM(*ps1));
  else
    ret = ustrp__dupx_buf(p, USTR__DUPX_FROM(*ps1), ustr_cstr(*ps1), clen);

  if (!ret)
    return (USTR_FALSE);
  
  ustrp__sc_free2(p, ps1, ret);

  return (USTR_TRUE);
}
USTR_CONF_I_PROTO int ustr_sc_ensure_owner(struct Ustr **ps1)
{ return (ustrp__sc_ensure_owner(0, ps1)); }
USTR_CONF_I_PROTO
int ustrp_sc_ensure_owner(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  int ret = ustrp__sc_ensure_owner(p, &tmp);
  *ps1 = USTRP(tmp);
  return (ret);
}

USTR_CONF_i_PROTO char *ustrp__sc_wstr(struct Ustr_pool *p, struct Ustr **ps1)
{
  if (!ustrp__sc_ensure_owner(p, ps1))
    return (USTR_FALSE);

  return (ustr_wstr(*ps1));
}
USTR_CONF_I_PROTO char *ustr_sc_wstr(struct Ustr **ps1)
{ return (ustrp__sc_wstr(0, ps1)); }
USTR_CONF_I_PROTO char *ustrp_sc_wstr(struct Ustr_pool *p, struct Ustrp **ps1)
{
  struct Ustr *tmp = &(*ps1)->s;
  char *ret = ustrp__sc_wstr(p, &tmp);
  *ps1 = USTRP(tmp);
  return (ret);
}
