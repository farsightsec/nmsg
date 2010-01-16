/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_PARSE_H
#error " You should have already included ustr-parse.h, or just include ustr.h."
#endif

#if ! USTR_CONF_HAVE_STDINT_H
# define USTR__UMAX unsigned long
#else
# define USTR__UMAX uintmax_t
#endif

/* basically uses: [ ]*[-+](0b|0B|0o|0O|0x|0X|0)[0-9a-z_]+ */
USTR_CONF_e_PROTO
int ustr__parse_num_beg(const char **ptr, size_t *len,
                        unsigned int flags, int *tst_neg, int *tst_0,
                        unsigned int *ern)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_i_PROTO
int ustr__parse_num_beg(const char **ptr, size_t *len,
                        unsigned int flags, int *tst_neg, int *tst_0,
                        unsigned int *ern)
{
  unsigned int base = flags & USTR__MASK_PARSE_NUM_BASE;
  int auto_base = USTR_FALSE;

  if (!base)
    auto_base = USTR_TRUE;
  else if (base > 36)
    base = 36;
  else if (base == 1)
    ++base;

  if (flags & USTR_FLAG_PARSE_NUM_SPACE)
  {
    while (*len && (**ptr == ' '))
    {
      ++*ptr;
      --*len;
    }    

    if (!*len)
    {
      *ern = USTR_TYPE_PARSE_NUM_ERR_ONLY_S;
      return (0);
    }
  }

  if (!(flags & USTR_FLAG_PARSE_NUM_NO_BEG_PM))
  {
    switch (**ptr)
    {
      case '-':
        *tst_neg = USTR_TRUE;
      case '+':
        ++*ptr;
        --*len;
    }
    if (!*len)
    {
      *ern = USTR_TYPE_PARSE_NUM_ERR_ONLY_SPM;
      return (0);
    }
  }

  if (**ptr != '0')
  {
    if (base)
      return (base);
    return (10);
  }
  
  ++*ptr;
  --*len;
  
  if (!*len)
  {
    *tst_0 = USTR_TRUE;    
    return (10);
  }
  else if ((auto_base || (base ==  2)) && ((**ptr == 'b') || (**ptr == 'B')))
    base =  2;
  else if ((auto_base || (base ==  8)) && ((**ptr == 'o') || (**ptr == 'O')))
    base =  8;
  else if ((auto_base || (base == 16)) && ((**ptr == 'x') || (**ptr == 'X')))
    base = 16;
  else if ((flags & USTR_FLAG_PARSE_NUM_NO_BEG_ZERO) &&
           (!auto_base || (**ptr == '0')))
  {
    *ern = USTR_TYPE_PARSE_NUM_ERR_BEG_ZERO;
    return (0);
  }
  else
  {
    *tst_0 = USTR_TRUE;
    if (base)
      return (base);
    return (8);
  }
  
  ++*ptr;
  --*len;
  
  if (!*len)
  {
    *ern = USTR_TYPE_PARSE_NUM_ERR_ONLY_SPMX;
    return (0);
  }

  if ((flags & USTR_FLAG_PARSE_NUM_NO_BEG_ZERO) && (**ptr == '0') && (*len > 1))
  {
    *ern = USTR_TYPE_PARSE_NUM_ERR_BEG_ZERO;
    return (0);
  }

  return (base);
}
#if USTR_CONF_HAVE_STDINT_H
USTR_CONF_I_PROTO
#else
USTR_CONF_e_PROTO
USTR__UMAX ustr_parse_uintmaxx(const struct Ustr *, size_t, unsigned int,
                               USTR__UMAX, USTR__UMAX, char,
                               size_t *, unsigned int *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1));
USTR_CONF_i_PROTO
#endif
USTR__UMAX ustr_parse_uintmaxx(const struct Ustr *s1, size_t off,
                               unsigned int flags,
                               USTR__UMAX num_min, USTR__UMAX num_max,
                               const char *sep,
                               size_t *ret_len, unsigned int *ern)
{
  static const char local_let_low[]  = "abcdefghijklmnopqrstuvwxyz";
  static const char local_let_high[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  unsigned int dummy_ern;
  unsigned int num_base = 0;
  int tst_neg   = USTR_FALSE;
  int tst_0     = USTR_FALSE;
  int done_once = USTR_FALSE;
  char num_end = '9';
  const char *ptr = ustr_cstr(s1);
  size_t      len = ustr_len(s1);
  size_t orig_len;
  USTR__UMAX ret = 0;
  size_t slen = strlen(sep);
  
  USTR_ASSERT(ustr_assert_valid(s1));
  USTR_ASSERT(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE) || !num_min);
  
  if (!ern) ern = &dummy_ern;
  *ern = USTR_TYPE_PARSE_NUM_ERR_NONE;

  USTR_ASSERT_RET(off <= len, 0);
  ptr += off;
  len -= off;
  
  orig_len = len;
  
  if (!(num_base = ustr__parse_num_beg(&ptr,&len, flags, &tst_neg,&tst_0, ern)))
    return (0);

  if (tst_neg && (flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE))
  {
    *ern = USTR_TYPE_PARSE_NUM_ERR_NEGATIVE;
    return (0);
  }
  
  if (num_base < 10)
    num_end = '0' + num_base - 1;

  if (tst_neg)
    num_max = num_min;
  
  done_once = tst_0;
  while (len)
  {
    const char *end = 0;
    unsigned int add_num = 0;
    USTR__UMAX old_ret = ret;
      
    if (done_once && (flags & USTR_FLAG_PARSE_NUM_SEP) &&
        (*ptr == *sep) && (len >= slen) && !memcmp(ptr, sep, slen))
    {
      ptr += slen;
      len -= slen;
      continue;
    }
    else
    {
      if ((*ptr >= '0') && (*ptr <= num_end))
        add_num = (*ptr - '0');
      else if (num_base <= 10)
        break;
      else if ((end = memchr(local_let_low,  *ptr, num_base - 10)))
        add_num = 10 + (end - local_let_low);
      else if ((end = memchr(local_let_high, *ptr, num_base - 10)))
        add_num = 10 + (end - local_let_high);
      else
        break;
    }
    
    ret = (ret * num_base) + add_num;
    if ((flags & USTR_FLAG_PARSE_NUM_OVERFLOW) &&
        (((ret - add_num) / num_base) != old_ret))
    {
      *ern = USTR_TYPE_PARSE_NUM_ERR_OVERFLOW;
      ret = 0;
      break;
    }

    ++ptr;
    --len;
    done_once = USTR_TRUE;
  }

  if (!done_once)
  {
    *ern = USTR_TYPE_PARSE_NUM_ERR_OOB;
    return (0);
  }
  
  if (!*ern && (flags & USTR_FLAG_PARSE_NUM_EXACT) && len)
    *ern = USTR_TYPE_PARSE_NUM_ERR_OOB;

  if (ret > num_max)
  {
    ret = num_max;
    if (flags & USTR_FLAG_PARSE_NUM_OVERFLOW)
    {
      if (!*ern)
        *ern = USTR_TYPE_PARSE_NUM_ERR_OVERFLOW;
      ret = 0;
    }
  }

  if (ret_len)
    *ret_len = orig_len - len;
  
  if (tst_neg)
    return (-ret);
  
  return (ret);
}

#if USTR_CONF_HAVE_STDINT_H
USTR_CONF_I_PROTO
uintmax_t ustr_parse_uintmax(const struct Ustr *s1, size_t off,
                             unsigned int flags, size_t *len, unsigned int *ern)
{
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  flags |= USTR_FLAG_PARSE_NUM_NO_NEGATIVE;
  return (ustr_parse_uintmaxx(s1, off, flags, 0, UINTMAX_MAX, "_", len, ern));
}
USTR_CONF_I_PROTO
intmax_t ustr_parse_intmax(const struct Ustr *s1, size_t off,
                           unsigned int flags, size_t *len, unsigned int *ern)
{
  uintmax_t num_min = INTMAX_MIN;
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  return (ustr_parse_uintmaxx(s1,off, flags, -num_min,INTMAX_MAX, "_",len,ern));
}
#endif

USTR_CONF_I_PROTO
unsigned long ustr_parse_ulongx(const struct Ustr *s1, size_t off,
                                unsigned int flags,
                                unsigned long num_min, unsigned long num_max,
                                const char *sep, size_t *len, unsigned int *ern)
{ return (ustr_parse_uintmaxx(s1,off, flags, num_min,num_max, sep, len, ern)); }

USTR_CONF_I_PROTO
unsigned long ustr_parse_ulong(const struct Ustr *s1, size_t off,
                               unsigned int flags,
                               size_t *len, unsigned int *ern)
{
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  flags |= USTR_FLAG_PARSE_NUM_NO_NEGATIVE;
  return (ustr_parse_uintmaxx(s1, off, flags, 0, ULONG_MAX, "_", len, ern));
}
USTR_CONF_I_PROTO
long ustr_parse_long(const struct Ustr *s1, size_t off, unsigned int flags,
                     size_t *len, unsigned int *ern)
{
  unsigned long num_min = LONG_MIN;
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  return (ustr_parse_uintmaxx(s1,off, flags, -num_min, LONG_MAX, "_", len,ern));
}

USTR_CONF_I_PROTO
unsigned int ustr_parse_uint(const struct Ustr *s1, size_t off,
                             unsigned int flags, size_t *len, unsigned int *ern)
{
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  flags |= USTR_FLAG_PARSE_NUM_NO_NEGATIVE;
  return (ustr_parse_uintmaxx(s1, off, flags, 0, UINT_MAX, "_", len, ern));
}
USTR_CONF_I_PROTO
int ustr_parse_int(const struct Ustr *s1, size_t off, unsigned int flags,
                   size_t *len, unsigned int *ern)
{
  unsigned int num_min = INT_MIN;
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  return (ustr_parse_uintmaxx(s1,off, flags, -num_min, INT_MAX, "_", len, ern));
}

USTR_CONF_I_PROTO
unsigned short ustr_parse_ushort(const struct Ustr *s1, size_t off,
                                 unsigned int flags,
                                 size_t *len, unsigned int *ern)
{
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  flags |= USTR_FLAG_PARSE_NUM_NO_NEGATIVE;
  return (ustr_parse_uintmaxx(s1, off, flags, 0, USHRT_MAX, "_", len, ern));
}
USTR_CONF_I_PROTO
short ustr_parse_short(const struct Ustr *s1, size_t off, unsigned int flags,
                       size_t *len, unsigned int *ern)
{
  unsigned short num_min = SHRT_MIN;
  ustr_assert(!(flags & USTR_FLAG_PARSE_NUM_NO_NEGATIVE));
  return (ustr_parse_uintmaxx(s1,off, flags, -num_min, SHRT_MAX, "_", len,ern));
}

/* void *ustr_parse_num(const struct Ustr *s1, unsigned int flags,
                        unsigned int *ern,
                        void *(*func)(unsigned int, int,unsigned int *, void *),
                        void *data)

  if (is_neg) add_num = -add_num;
  
  if (!(ret = func(num_base, add_num, err, ret)) && !*err)
    return (NULL);
*/

