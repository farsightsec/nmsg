/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */

#ifndef USTR_MAIN_H
#error " You should have already included ustr-main.h, or just include ustr.h."
#endif

/* not sure of the version */
#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && (__GNUC__ > 3) && \
    USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_H() __attribute__((visibility("hidden")))
#else
# define USTR__COMPILE_ATTR_H()
#endif

#include <stdarg.h> /* va_list for va_arg() functionality */

/* second set of defaults... *sigh* */
struct Ustr_opts USTR__COMPILE_ATTR_H() ustr__opts[1] = {
 {1, /* ref bytes */
  {ustr__cntl_mc_setup_malloc, /* malloc be called first */
   realloc,
   free}, /* Ustr_cntl_mem */
  {vsnprintf, vsnprintf}, /* fmt */
  USTR_FALSE,   /* has_size */
  USTR_FALSE,   /* exact_bytes */
  USTR_FALSE,   /* scrub on malloc */
  USTR_FALSE,   /* scrub on free */
  USTR_FALSE    /* scrub on realloc */
 }};

/* not namespaced because this must be in a C-file. */
#ifndef USE_MALLOC_CHECK
#define USE_MALLOC_CHECK 1
#endif
#define MALLOC_CHECK_API_M_SCRUB ustr__opts->mc_m_scrub
#define MALLOC_CHECK_API_F_SCRUB ustr__opts->mc_f_scrub
#define MALLOC_CHECK_API_R_SCRUB ustr__opts->mc_r_scrub
#define MALLOC_CHECK_SCOPE_EXTERN 0
#include "malloc-check.h"

MALLOC_CHECK_DECL();

typedef struct Ustr__cntl_mc_ptrs
{
 const char *file;
 unsigned int line;
 const char *func;
} Ustr__cntl_mc_ptrs;
Ustr__cntl_mc_ptrs USTR__COMPILE_ATTR_H() *ustr__cntl_mc_ptr = 0;
size_t             USTR__COMPILE_ATTR_H()  ustr__cntl_mc_num = 0;
size_t             USTR__COMPILE_ATTR_H()  ustr__cntl_mc_sz  = 0;

#define USTR__STREQ(x, y) !strcmp(x, y)

USTR_CONF_i_PROTO int   ustr__cntl_mc_setup_env2bool(const char *key, int def)
{
  const char *ptr = getenv(key);

  if (!ptr)                    return (!!def);

  if (USTR__STREQ(ptr, "1"))   return (USTR_TRUE);
  if (USTR__STREQ(ptr, "on"))  return (USTR_TRUE);
  if (USTR__STREQ(ptr, "yes")) return (USTR_TRUE);

  if (USTR__STREQ(ptr, "0"))   return (USTR_FALSE);
  if (USTR__STREQ(ptr, "off")) return (USTR_FALSE);
  if (USTR__STREQ(ptr, "no"))  return (USTR_FALSE);

                               return (!!def);
}

USTR_CONF_i_PROTO void  ustr__cntl_mc_setup_main(void)
{
  int val = 0;
  
  if (!ustr__cntl_mc_setup_env2bool("USTR_CNTL_MC", USTR_CONF_USE_ASSERT))
  {
    ustr__opts->umem.sys_malloc  = malloc;
    ustr__opts->umem.sys_realloc = realloc;
    ustr__opts->umem.sys_free    = free;
    
    return;
  }

  val = ustr__opts->mc_m_scrub;
  val = ustr__cntl_mc_setup_env2bool("USTR_CNTL_MC_M_SCRUB", val);
  ustr__opts->mc_m_scrub = val;

  val = ustr__opts->mc_f_scrub;
  val = ustr__cntl_mc_setup_env2bool("USTR_CNTL_MC_F_SCRUB", val);
  ustr__opts->mc_f_scrub = val;
  
  val = ustr__opts->mc_r_scrub;
  val = ustr__cntl_mc_setup_env2bool("USTR_CNTL_MC_R_SCRUB", val);
  ustr__opts->mc_r_scrub = val;

  USTR_CNTL_MALLOC_CHECK_BEG(USTR_TRUE);
}

USTR_CONF_i_PROTO void *ustr__cntl_mc_setup_malloc(size_t x)
{ /* again, it's not possible to call anything but malloc() or free(NULL).
   * So just doing setup here is fine. */
  ustr__cntl_mc_setup_main();
  return (ustr__opts->umem.sys_malloc(x));
}

USTR_CONF_i_PROTO void *ustr__cntl_mc_malloc(size_t x)
{
  struct Ustr__cntl_mc_ptrs *ptr = ustr__cntl_mc_ptr;
  size_t num = ustr__cntl_mc_num;
  
  return (malloc_check_malloc(x, ptr[num].file, ptr[num].line, ptr[num].func));
}
USTR_CONF_i_PROTO void *ustr__cntl_mc_realloc(void *p, size_t x)
{
  struct Ustr__cntl_mc_ptrs *ptr = ustr__cntl_mc_ptr;
  size_t num = ustr__cntl_mc_num;
  
  return (malloc_check_realloc(p,x, ptr[num].file,ptr[num].line,ptr[num].func));
}
USTR_CONF_i_PROTO void  ustr__cntl_mc_free(void *x)
{
  struct Ustr__cntl_mc_ptrs *ptr = ustr__cntl_mc_ptr;
  size_t num = ustr__cntl_mc_num;
  
  malloc_check_free(x, ptr[num].file, ptr[num].line, ptr[num].func);
}

USTR_CONF_I_PROTO int ustr_cntl_opt(int option, ...)
{
  int ret = USTR_FALSE;
  va_list ap;

  va_start(ap, option);

  switch (option)
  {
    case USTR_CNTL_OPT_GET_REF_BYTES:
    {
      size_t *val = va_arg(ap, size_t *);

      *val = ustr__opts->ref_bytes;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_REF_BYTES:
    {
      size_t rbytes = va_arg(ap, size_t);

      USTR_ASSERT_RET((rbytes == 0) ||
                      (rbytes == 1) || (rbytes == 2) || (rbytes == 4) ||
                      (USTR_CONF_HAVE_64bit_SIZE_MAX && (rbytes == 8)),
                      USTR_FALSE);

      ustr__opts->ref_bytes = rbytes;
      
      ret = USTR_TRUE;
    }
    break;

    case USTR_CNTL_OPT_GET_HAS_SIZE:
    {
      int *val = va_arg(ap, int *);

      *val = ustr__opts->has_size;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_HAS_SIZE:
    {
      int val = va_arg(ap, int);

      USTR_ASSERT_RET((val == !!val), USTR_FALSE);

      ustr__opts->has_size = val;
      
      ret = USTR_TRUE;
    }
    break;

    case USTR_CNTL_OPT_GET_EXACT_BYTES:
    {
      int *val = va_arg(ap, int *);

      *val = ustr__opts->exact_bytes;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_EXACT_BYTES:
    {
      int val = va_arg(ap, int);

      USTR_ASSERT_RET((val == !!val), USTR_FALSE);

      ustr__opts->exact_bytes = val;
      
      ret = USTR_TRUE;
    }
    break;

    /* call backs */
    
    case USTR_CNTL_OPT_GET_MEM:
    {
      struct Ustr_cntl_mem *val = va_arg(ap, struct Ustr_cntl_mem *);

      val->sys_malloc  = ustr__opts->umem.sys_malloc;
      val->sys_realloc = ustr__opts->umem.sys_realloc;
      val->sys_free    = ustr__opts->umem.sys_free;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_MEM:
    {
      const struct Ustr_cntl_mem *val = va_arg(ap, struct Ustr_cntl_mem *);

      ustr__opts->umem.sys_malloc  = val->sys_malloc;
      ustr__opts->umem.sys_realloc = val->sys_realloc;
      ustr__opts->umem.sys_free    = val->sys_free;
      
      ret = USTR_TRUE;
    }
    break;

    case USTR_CNTL_OPT_GET_MC_M_SCRUB:
    {
      int *val = va_arg(ap, int *);

      *val = ustr__opts->mc_m_scrub;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_MC_M_SCRUB:
    {
      int val = va_arg(ap, int);
      
      USTR_ASSERT_RET((val == !!val), USTR_FALSE);
      
      ustr__opts->mc_m_scrub = val;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_GET_MC_F_SCRUB:
    {
      int *val = va_arg(ap, int *);

      *val = ustr__opts->mc_f_scrub;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_MC_F_SCRUB:
    {
      int val = va_arg(ap, int);
      
      USTR_ASSERT_RET((val == !!val), USTR_FALSE);
      
      ustr__opts->mc_f_scrub = val;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_GET_MC_R_SCRUB:
    {
      int *val = va_arg(ap, int *);

      *val = ustr__opts->mc_r_scrub;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_MC_R_SCRUB:
    {
      int val = va_arg(ap, int);
      
      USTR_ASSERT_RET((val == !!val), USTR_FALSE);
      
      ustr__opts->mc_r_scrub = val;
      
      ret = USTR_TRUE;
    }
    break;
      
    case 666:
    {
      unsigned long valT = va_arg(ap, unsigned long);
      int enabled = !!ustr__cntl_mc_sz;

      USTR_ASSERT(ustr__cntl_mc_num <= ustr__cntl_mc_sz);
      
      if (valT == 0x0FFE)
      {
        ret = ustr__cntl_mc_num + enabled;
        break;
      }
      
      switch (valT)
      {
        case 0xF0F0:
        case 0xF0F1:
        case 0x0FF0:
        case 0x0FF1:
        case 0x0FF2:
        case 0x0FF3:
        case 0x0FF4:
        case 0x0FFF:
          ret = USTR_TRUE;
      }
      USTR_ASSERT(ret);

      if (!enabled && (valT == 0x0FFF))
      {
        ret = USTR_FALSE;
        break;
      }      
      if (!enabled && (valT != 0x0FF0))
        break; /* pretend it worked */
      
      switch (valT)
      {
        case 0xF0F0:
        {
          unsigned long valV = va_arg(ap, unsigned long);
          MALLOC_CHECK_FAIL_IN(valV);
        }
        break;

        case 0xF0F1:
        {
          unsigned long *valV = va_arg(ap, unsigned long *);
          *valV = MALLOC_CHECK_STORE.mem_fail_num;
        }
        break;
        
        case 0x0FF0:
        {
          const char  *file = va_arg(ap, char *);
          unsigned int line = va_arg(ap, unsigned int);
          const char  *func = va_arg(ap, char *);
          struct Ustr__cntl_mc_ptrs *tptr = ustr__cntl_mc_ptr;
          size_t tsz = 3;

          if (!enabled)
            tptr = MC_MALLOC(sizeof(Ustr__cntl_mc_ptrs) * tsz);
          else if (++ustr__cntl_mc_num >= ustr__cntl_mc_sz)
          {
            tsz = (ustr__cntl_mc_sz * 2) + 1;
            tptr = MC_REALLOC(tptr, sizeof(Ustr__cntl_mc_ptrs) * tsz);
          }
          
          if (!tptr)
          {
            if (enabled)
              --ustr__cntl_mc_num;
            ret = USTR_FALSE;
            break;
          }

          if (!enabled)
          {
            ustr__opts->umem.sys_malloc  = ustr__cntl_mc_malloc;
            ustr__opts->umem.sys_realloc = ustr__cntl_mc_realloc;
            ustr__opts->umem.sys_free    = ustr__cntl_mc_free;
          }
          
          ustr__cntl_mc_ptr = tptr;
          ustr__cntl_mc_sz  = tsz;
          
          ustr__cntl_mc_ptr[ustr__cntl_mc_num].file = file;
          ustr__cntl_mc_ptr[ustr__cntl_mc_num].line = line;
          ustr__cntl_mc_ptr[ustr__cntl_mc_num].func = func;
        }
        break;

        case 0x0FF1:
        {
          struct Ustr__cntl_mc_ptrs *ptr = ustr__cntl_mc_ptr;
          size_t num = ustr__cntl_mc_num;
          void *valP = va_arg(ap, void *);
          malloc_check_mem(valP, ptr[num].file, ptr[num].line, ptr[num].func);
        }
        break;

        case 0x0FF2:
        {
          struct Ustr__cntl_mc_ptrs *ptr = ustr__cntl_mc_ptr;
          size_t num = ustr__cntl_mc_num;
          void *valP  = va_arg(ap, void *);
          size_t valV = va_arg(ap, size_t);
          malloc_check_mem_sz(valP, valV,
                              ptr[num].file, ptr[num].line, ptr[num].func);
        }
        break;

        case 0x0FF3:
        {
          struct Ustr__cntl_mc_ptrs *ptr = ustr__cntl_mc_ptr;
          size_t num = ustr__cntl_mc_num;
          void *valP  = va_arg(ap, void *);
          size_t valV = va_arg(ap, size_t);
          malloc_check_mem_minsz(valP, valV,
                                 ptr[num].file, ptr[num].line, ptr[num].func);
        }
        break;

        case 0x0FF4:
        { /* needed for realloc() down doesn't fail */
          struct Ustr__cntl_mc_ptrs *ptr_mc = ustr__cntl_mc_ptr;
          size_t num_mc = ustr__cntl_mc_num;
          void *ptr = va_arg(ap, void *);
          size_t nsz = va_arg(ap, size_t);
          unsigned int scan = malloc_check_mem(ptr,
                                               ptr_mc[num_mc].file,
                                               ptr_mc[num_mc].line,
                                               ptr_mc[num_mc].func);

          MALLOC_CHECK_STORE.mem_vals[scan].sz = nsz;
        }
        break;

        case 0x0FFF:
        {
          const char  *file = va_arg(ap, char *);
          unsigned int line = va_arg(ap, unsigned int);
          const char  *func = va_arg(ap, char *);

          if (ustr__cntl_mc_num)
          {
            USTR_ASSERT(!strcmp(file,
                                ustr__cntl_mc_ptr[ustr__cntl_mc_num].file));
            USTR_ASSERT(line); /* can't say much about this */
            USTR_ASSERT(!strcmp(func,
                                ustr__cntl_mc_ptr[ustr__cntl_mc_num].func));
          
            --ustr__cntl_mc_num;
            break;
          }

          MC_FREE(ustr__cntl_mc_ptr);
          ustr__cntl_mc_num = 0;
          ustr__cntl_mc_sz  = 0;
          ustr__cntl_mc_ptr = 0;
          
          /* it's bad otherwise */
          malloc_check_empty(file, line, func);
          
          ustr__opts->umem.sys_malloc  = malloc;
          ustr__opts->umem.sys_realloc = realloc;
          ustr__opts->umem.sys_free    = free;
          
          MALLOC_CHECK_STORE.mem_num      = 0;
          MALLOC_CHECK_STORE.mem_fail_num = 0;
        }
        break;
      }
    }
    break;
    
    case USTR_CNTL_OPT_GET_FMT:
    {
      struct Ustr_cntl_fmt *val = va_arg(ap, struct Ustr_cntl_fmt *);

      val->sys_vsnprintf_beg = ustr__opts->ufmt.sys_vsnprintf_beg;
      val->sys_vsnprintf_end = ustr__opts->ufmt.sys_vsnprintf_end;
      
      ret = USTR_TRUE;
    }
    break;
    
    case USTR_CNTL_OPT_SET_FMT:
    {
      const struct Ustr_cntl_fmt *val = va_arg(ap, struct Ustr_cntl_fmt *);

      ustr__opts->ufmt.sys_vsnprintf_beg = val->sys_vsnprintf_beg;
      ustr__opts->ufmt.sys_vsnprintf_end = val->sys_vsnprintf_end;
      
      ret = USTR_TRUE;
    }
    /* break; */

    USTR_ASSERT_NO_SWITCH_DEF("Bad option passed to ustr_cntl_opt()");
  }
  
  va_end(ap);

  return (ret);
}
