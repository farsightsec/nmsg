/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_POOL_H
#error " You should have already included ustr-pool.h, or just include ustr.h."
#endif

struct Ustr__pool_ll_node
{
 struct Ustr__pool_ll_node *next;
 void *ptr;
};

struct Ustr__pool_ll_base
{ /* "simple" pool implementation */
 struct Ustr_pool cbs;
 struct Ustr__pool_ll_node *beg;
 
 struct Ustr__pool_ll_base *sbeg; /* wasting a lot of space for sub pools */
 struct Ustr__pool_ll_base *base;
 struct Ustr__pool_ll_base *next;
 struct Ustr__pool_ll_base *prev;

 unsigned int free_num : 30; /* how many nodes we search to free */

 unsigned int call_realloc : 1;
};

#define USTR__POOL_LL_SIB_NULL ((struct Ustr__pool_ll_base *) 0)

USTR_CONF_e_PROTO void *ustr__pool_ll_sys_malloc(struct Ustr_pool *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A()
    USTR__COMPILE_ATTR_MALLOC();
USTR_CONF_e_PROTO
void *ustr__pool_ll_sys_realloc(struct Ustr_pool *, void *, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1))
    USTR__COMPILE_ATTR_MALLOC();
USTR_CONF_e_PROTO void ustr__pool_ll_sys_free(struct Ustr_pool *, void *)
    USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_e_PROTO
struct Ustr_pool *ustr__pool_ll_make_subpool(struct Ustr_pool *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_MALLOC();
USTR_CONF_e_PROTO void ustr__pool_ll__clear(struct Ustr__pool_ll_base *, int);
USTR_CONF_e_PROTO void ustr__pool_ll_clear(struct Ustr_pool *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_e_PROTO void ustr__pool_ll__free(struct Ustr__pool_ll_base *, int);
USTR_CONF_e_PROTO void ustr__pool_ll_free(struct Ustr_pool *);

USTR_CONF_i_PROTO void *ustr__pool_ll_sys_malloc(struct Ustr_pool *p,size_t len)
{
  struct Ustr__pool_ll_base *sip = (struct Ustr__pool_ll_base *)p;
  struct Ustr__pool_ll_node *np;
  void *ret = USTR_CONF_MALLOC(len);

  ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(p,
                                            sizeof(struct Ustr__pool_ll_base)));
  
  if (!ret)
    return (ret);

  if (!(np = USTR_CONF_MALLOC(sizeof(struct Ustr__pool_ll_node))))
  {
    USTR_CONF_FREE(ret);
    return (0);
  }

  np->next = sip->beg;
  sip->beg = np;
  np->ptr  = ret;
  
  return (ret);
}

USTR_CONF_i_PROTO
void *ustr__pool_ll_sys_realloc(struct Ustr_pool *p, void *old,
                                size_t olen, size_t nlen)
{
  struct Ustr__pool_ll_base *sip = (struct Ustr__pool_ll_base *)p;
  void *ret = 0;

  ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(p,
                                            sizeof(struct Ustr__pool_ll_base)));
  USTR_ASSERT((old && sip->beg && sip->beg->ptr) || !olen);
  ustr_assert(olen ? USTR_CNTL_MALLOC_CHECK_MEM_MINSZ(old, olen) :
              (!old || USTR_CNTL_MALLOC_CHECK_MEM(old)));

  if (!nlen)
    ++nlen;
  
  if (olen && (sip->beg->ptr == old) && sip->call_realloc)
  { /* let the last allocated Ustrp grow/shrink */
    if ((ret = USTR_CONF_REALLOC(old, nlen)))
      sip->beg->ptr = ret;
  }
  else if (olen >= nlen) /* always allow reductions/nothing */
  {
    USTR__CNTL_MALLOC_CHECK_FIXUP_REALLOC(old, nlen);
    return (old);
  }
  else if ((ret = ustr__pool_ll_sys_malloc(p, nlen)))
    memcpy(ret, old, olen);
  
  return (ret);
}

USTR_CONF_i_PROTO
void ustr__pool_ll_sys_free(struct Ustr_pool *p, void *old)
{
  struct Ustr__pool_ll_base *sip = (struct Ustr__pool_ll_base *)p;
  struct Ustr__pool_ll_node **op = &sip->beg;
  unsigned int num = sip->free_num;

  ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(p,
                                            sizeof(struct Ustr__pool_ll_base)));
  ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM(old));
  
  while (*op && num--)
  {
    if ((*op)->ptr == old)
    {
      struct Ustr__pool_ll_node *rm = *op;
      
      *op = rm->next;
      
      USTR_CONF_FREE(rm->ptr);
      USTR_CONF_FREE(rm);
      return;
    }
    
    op = &(*op)->next;
  }
}

USTR_CONF_i_PROTO void ustr__pool_ll__clear(struct Ustr__pool_ll_base *base,
                                            int siblings)
{
  struct Ustr__pool_ll_node *scan;
  
  if (!base)
    return;

  scan = base->beg;
  while (scan)
  {
    struct Ustr__pool_ll_node *scan_next = scan->next;

    USTR_CONF_FREE(scan->ptr);
    USTR_CONF_FREE(scan);

    scan = scan_next;
  }
  base->beg = 0;

  if (siblings)
    ustr__pool_ll__clear(base->next, USTR_TRUE);

  ustr__pool_ll__clear(base->sbeg, USTR_TRUE);
}
USTR_CONF_i_PROTO void ustr__pool_ll_clear(struct Ustr_pool *base)
{
  ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(base,
                                            sizeof(struct Ustr__pool_ll_base)));
  ustr__pool_ll__clear((struct Ustr__pool_ll_base *)base, USTR_FALSE);
}

USTR_CONF_i_PROTO void ustr__pool_ll__free(struct Ustr__pool_ll_base *base,
                                           int siblings)
{
  if (!base)
    return;
  
  if (siblings)
    ustr__pool_ll__free(base->next, USTR_TRUE);
  ustr__pool_ll__free(base->sbeg, USTR_TRUE);
  base->sbeg = 0;
  
  ustr__pool_ll__clear(base, USTR_FALSE);
  USTR_CONF_FREE(base);
}
USTR_CONF_i_PROTO void ustr__pool_ll_free(struct Ustr_pool *p)
{
  struct Ustr__pool_ll_base *sip = (struct Ustr__pool_ll_base *)p;
  
  ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(p,
                                            sizeof(struct Ustr__pool_ll_base)));

  if (sip->prev)
    sip->prev->next = sip->next;
  else if (sip->base)
    sip->base->sbeg = sip->next;

  if (sip->next)
    sip->next->prev = sip->prev;
  
  ustr__pool_ll__free(sip, USTR_FALSE);
}

USTR_CONF_i_PROTO
struct Ustr_pool *ustr__pool_ll_make_subpool(struct Ustr_pool *p)
{
  struct Ustr__pool_ll_base *sip = (struct Ustr__pool_ll_base *)p;
  struct Ustr__pool_ll_base *tmp;

  if (!(tmp = USTR_CONF_MALLOC(sizeof(struct Ustr__pool_ll_base))))

    return (USTR_POOL_NULL);

  tmp->cbs.pool_sys_malloc   = ustr__pool_ll_sys_malloc;
  tmp->cbs.pool_sys_realloc  = ustr__pool_ll_sys_realloc;
  tmp->cbs.pool_sys_free     = ustr__pool_ll_sys_free;

  tmp->cbs.pool_make_subpool = ustr__pool_ll_make_subpool;
  tmp->cbs.pool_clear        = ustr__pool_ll_clear;
  tmp->cbs.pool_free         = ustr__pool_ll_free;

  tmp->beg  = 0;
  tmp->sbeg = USTR__POOL_LL_SIB_NULL;
  tmp->prev = USTR__POOL_LL_SIB_NULL;

  tmp->next = USTR__POOL_LL_SIB_NULL;
  tmp->base = USTR__POOL_LL_SIB_NULL;

  tmp->free_num = 2; /* magic number, allows dupx + copy + free */

  tmp->call_realloc = USTR_TRUE;
  
  if (!p)
    return (&tmp->cbs);
  
  ustr_assert(USTR_CNTL_MALLOC_CHECK_MEM_SZ(p,
                                            sizeof(struct Ustr__pool_ll_base)));

  if ((tmp->next = sip->sbeg))
    tmp->next->prev = tmp;
  sip->sbeg = tmp;

  tmp->base = sip;
  
  return (&tmp->cbs);
}

/* linked list pool API */
USTR_CONF_I_PROTO struct Ustr_pool *ustr_pool_ll_make(void)
{ return (ustr__pool_ll_make_subpool(USTR_POOL_NULL)); }

#include <stdarg.h> /* va_list for va_arg() functionality */

USTR_CONF_I_PROTO
int ustr_pool_ll_cntl(struct Ustr_pool *p, int option, ...)
{
  struct Ustr__pool_ll_base *sip = (struct Ustr__pool_ll_base *)p;
  int ret = USTR_FALSE;
  va_list ap;
  
  va_start(ap, option);

  switch (option)
  {
    case USTR_POOL_LL_CNTL_GET_FREE_CMP:
    {
      unsigned int *num = va_arg(ap, unsigned int *);
   
      *num = sip->free_num;

      ret = USTR_TRUE;
    }
    break;
    case USTR_POOL_LL_CNTL_SET_FREE_CMP:
    {
      unsigned int num = va_arg(ap, unsigned int);
      
      USTR_ASSERT_RET((num <= 65535), USTR_FALSE); /* 2 ** 16 */
   
      sip->free_num = num;

      ret = USTR_TRUE;
    }
    break;
    
    case USTR_POOL_LL_CNTL_GET_REALLOC:
    {
      int *toggle = va_arg(ap, int *);
      
      *toggle = sip->call_realloc;

      ret = USTR_TRUE;
    }
    break;
    case USTR_POOL_LL_CNTL_SET_REALLOC:
    {
      int toggle = va_arg(ap, int);
      
      USTR_ASSERT_RET((toggle == !!toggle), USTR_FALSE);
      
      sip->call_realloc = toggle;

      ret = USTR_TRUE;
    }
    break;
  }
  
  USTR_ASSERT(ret);
  
  va_end(ap);

  return (ret);
}

/* "block" pool API */
/* USTR_CONF_I_PROTO struct Ustr_pool *ustr_pool_blk_make(void)
   { return (ustr__pool_blk_make_subpool(USTR_POOL_NULL)); } */

/* choose one of the above -- linked list */
USTR_CONF_I_PROTO struct Ustr_pool *ustr_pool_make_pool(void)
{ return (ustr__pool_ll_make_subpool(USTR_POOL_NULL)); }

