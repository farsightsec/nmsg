#ifndef MALLOC_CHECK_H
#define MALLOC_CHECK_H 1

#ifndef  MALLOC_CHECK__ATTR_USED
#if defined(__GNUC__) && (__GNUC__ > 3) /* not sure */
# define MALLOC_CHECK__ATTR_USED() __attribute__((__used__))
#else
# define MALLOC_CHECK__ATTR_USED() /* do nothing */
#endif
#endif

#ifndef  MALLOC_CHECK__ATTR_H
#if defined(__GNUC__) && (__GNUC__ > 3) /* not sure */
# define MALLOC_CHECK__ATTR_H() __attribute__((__visibility__("hidden")))
#else
# define MALLOC_CHECK__ATTR_H() /* do nothing */
#endif
#endif

#ifndef  MALLOC_CHECK__ATTR_MALLOC
#if defined(__GNUC__) && (__GNUC__ > 3) /* not sure */
# define MALLOC_CHECK__ATTR_MALLOC() __attribute__ ((__malloc__))
#else
# define MALLOC_CHECK__ATTR_MALLOC() /* do nothing */
#endif
#endif

#ifndef MALLOC_CHECK_API_M_SCRUB /* memset data at ptr's on malloc */
#define MALLOC_CHECK_API_M_SCRUB 0
#endif

#ifndef MALLOC_CHECK_API_F_SCRUB /* memset data at ptr's on free */
#define MALLOC_CHECK_API_F_SCRUB 0
#endif

#ifndef MALLOC_CHECK_API_R_SCRUB /* never really call realloc() */
#define MALLOC_CHECK_API_R_SCRUB 0
#endif

#ifndef MALLOC_CHECK_STORE
#define MALLOC_CHECK_STORE malloc_check__app_store
#endif

/* NOTE: don't reset fail nums */
#define MALLOC_CHECK_REINIT()                         \
    MALLOC_CHECK_STORE.mem_sz = 0;                   \
    MALLOC_CHECK_STORE.mem_num = 0;                  \
    MALLOC_CHECK_STORE.mem_vals = NULL
#define MALLOC_CHECK_INIT()                           \
    MALLOC_CHECK_STORE.mem_fail_num = 0;             \
    MALLOC_CHECK_REINIT()

#ifndef USE_MALLOC_CHECK
#ifndef NDEBUG
#  define USE_MALLOC_CHECK 1
# else
#  define USE_MALLOC_CHECK 0
# endif
#endif

#ifndef MALLOC_CHECK_FUNC_NAME
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) ||       \
    (defined(__GNUC__) && (__GNUC__ > 3) && !defined(__STRICT_ANSI__))
# define MALLOC_CHECK_FUNC_NAME __func__
#else
# define MALLOC_CHECK_FUNC_NAME ""
#endif
#endif

#define MALLOC_CHECK_MEM(x)                                             \
    malloc_check_mem(x, __FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)
#define MALLOC_CHECK_MEM_SZ(x, y)                                       \
    malloc_check_mem_sz(x, y, __FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)
#define MALLOC_CHECK_MEM_MINSZ(x, y)                                    \
    malloc_check_mem_minsz(x, y, __FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)
#define MALLOC_CHECK_EMPTY()                                            \
    malloc_check_empty(__FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)

/* smaller because they will be called a _lot_ */
#define MC_MALLOC(x)                                                    \
    malloc_check_malloc(x, __FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)
#define MC_CALLOC(x, y)                                                 \
    malloc_check_calloc(x, y, __FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)
#define MC_REALLOC(x, y)                                                \
    malloc_check_realloc(x, y, __FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)
#define MC_FREE(x)                                                      \
    malloc_check_free(x, __FILE__, __LINE__, MALLOC_CHECK_FUNC_NAME)

#if !(USE_MALLOC_CHECK)
#define MALLOC_CHECK_DECL()                                     \
  static Malloc_check_store MALLOC_CHECK_STORE = {0, 0, 0, NULL}

# define MALLOC_CHECK_FAIL_IN(x) /* nothing */
# define MALLOC_CHECK_SCRUB_PTR(x, y)  /* nothing */

# define malloc_check_mem(x, Fi, L, Fu) (1)
# define malloc_check_mem_sz(x, y, Fi, L, Fu) (1)
# define malloc_check_mem_minsz(x, y, Fi, L, Fu) (1)
# define malloc_check_empty(Fi, L, Fu)  /* nothing */

# define malloc_check_malloc(x, Fi, L, Fu)     malloc(x)
# define malloc_check_calloc(x, y, Fi, L, Fu)  calloc(x, y)
# define malloc_check_realloc(x, y, Fi, L, Fu) realloc(x, y)
# define malloc_check_free(x, Fi, L, Fu)       free(x)

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Malloc_check_vals
{
 void *ptr;
 size_t sz;
 const char *file;
 unsigned int line;
 const char *func;
} Malloc_check_vals;

typedef struct Malloc_check_store
{
 unsigned long      mem_sz;
 unsigned long      mem_num;
 unsigned long      mem_fail_num;
 Malloc_check_vals *mem_vals;
} Malloc_check_store;

#ifndef MALLOC_CHECK_SCOPE_EXTERN
#define MALLOC_CHECK_SCOPE_EXTERN 1
#endif

#if MALLOC_CHECK_SCOPE_EXTERN
extern Malloc_check_store MALLOC_CHECK__ATTR_H() MALLOC_CHECK_STORE;
#else
static Malloc_check_store                        MALLOC_CHECK_STORE;
#endif

/* custom assert's so that we get the file/line numbers right, always ON */
#define malloc_check_assert(x) do {                                     \
      if (x) {} else {                                                  \
        fprintf(stderr, " -=> mc_assert (%s) failed, caller=%s:%s:%d.\n", \
                #x , func, file, line);                                 \
        abort(); }                                                      \
    } while (0)
#define MALLOC_CHECK_ASSERT(x) do {                                     \
      if (x) {} else {                                                  \
        fprintf(stderr, " -=> MC_ASSERT (%s) failed, caller=%s:%s:%d.\n", \
                #x , func, file, line);                                 \
        abort(); }                                                      \
    } while (0)

#if MALLOC_CHECK_SCOPE_EXTERN
#define MALLOC_CHECK_DECL()                                     \
    Malloc_check_store MALLOC_CHECK_STORE = {0, 0, 0, NULL}
#else
#define MALLOC_CHECK_DECL()                                     \
 static Malloc_check_store MALLOC_CHECK_STORE = {0, 0, 0, NULL}
#endif

# define MALLOC_CHECK_DEC()                                             \
    (MALLOC_CHECK_STORE.mem_fail_num && !--MALLOC_CHECK_STORE.mem_fail_num)
# define MALLOC_CHECK_FAIL_IN(x) MALLOC_CHECK_STORE.mem_fail_num = (x)
# define MALLOC_CHECK_SCRUB_PTR(x, y)  memset(x, 0xa5, y)

#ifndef MALLOC_CHECK_PRINT
#define MALLOC_CHECK_PRINT 1
#endif

#ifndef MALLOC_CHECK_TRACE
#define MALLOC_CHECK_TRACE 0
#endif

#ifndef MALLOC_CHECK_SWAP_TYPE
#define MALLOC_CHECK_SWAP_TYPE(x, y, type) do {              \
      type internal_local_tmp = (x);            \
      (x) = (y);                                \
      (y) = internal_local_tmp;                 \
    } while (0)
#endif

static void malloc_check_alloc(const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_USED();
static unsigned int malloc_check_mem(const void *, const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_USED();
static unsigned int malloc_check_mem_sz(const void *, size_t, const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_USED();
static unsigned int malloc_check_mem_minsz(const void *, size_t, const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_USED();
static void *malloc_check_malloc(size_t, const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_MALLOC() MALLOC_CHECK__ATTR_USED();
static void *malloc_check_calloc(size_t, size_t, const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_MALLOC() MALLOC_CHECK__ATTR_USED();
static void malloc_check_free(void *, const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_USED();
static void *malloc_check_realloc(void *, size_t,
                                  const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_MALLOC() MALLOC_CHECK__ATTR_USED();
static void malloc_check_empty(const char *, unsigned int, const char *)
   MALLOC_CHECK__ATTR_USED();

static
void malloc_check_alloc(const char *file, unsigned int line, const char *func)
{
  size_t sz = MALLOC_CHECK_STORE.mem_sz;
  
  ++MALLOC_CHECK_STORE.mem_num;

  if (!MALLOC_CHECK_STORE.mem_sz)
  {
    sz = 8;
    MALLOC_CHECK_STORE.mem_vals = malloc(sizeof(Malloc_check_vals) * sz);
  }
  else if (MALLOC_CHECK_STORE.mem_num > MALLOC_CHECK_STORE.mem_sz)
  {
    sz *= 2;
    MALLOC_CHECK_STORE.mem_vals = realloc(MALLOC_CHECK_STORE.mem_vals,
                                          sizeof(Malloc_check_vals) * sz);
  }
  malloc_check_assert(MALLOC_CHECK_STORE.mem_num <= sz);
  malloc_check_assert(MALLOC_CHECK_STORE.mem_vals);

  MALLOC_CHECK_STORE.mem_sz = sz;
}

static unsigned int malloc_check_mem(const void *ptr, const
                                     char *file, unsigned int line,
                                     const char *func)
{
  unsigned int scan = 0;

  malloc_check_assert(MALLOC_CHECK_STORE.mem_num);
    
  while (MALLOC_CHECK_STORE.mem_vals[scan].ptr &&
         (MALLOC_CHECK_STORE.mem_vals[scan].ptr != ptr))
    ++scan;
  
  malloc_check_assert(MALLOC_CHECK_STORE.mem_vals[scan].ptr);

  return (scan);
}

static unsigned int malloc_check_mem_sz(const void *ptr, size_t sz,
                                        const char *file, unsigned int line,
                                        const char *func)
{
  unsigned int scan = malloc_check_mem(ptr, file, line, func);

  malloc_check_assert(MALLOC_CHECK_STORE.mem_vals[scan].sz == sz);

  return (scan);
}

static unsigned int malloc_check_mem_minsz(const void *ptr, size_t sz,
                                           const char *file, unsigned int line,
                                           const char *func)
{
  unsigned int scan = malloc_check_mem(ptr, file, line, func);

  malloc_check_assert(MALLOC_CHECK_STORE.mem_vals[scan].sz >= sz);

  return (scan);
}

static void *malloc_check_malloc(size_t sz, const char *file, unsigned int line,
                                 const char *func)
{
  void *ret = NULL;

  if (MALLOC_CHECK_DEC())
    return (NULL);

  malloc_check_alloc(file, line, func);

  MALLOC_CHECK_ASSERT(sz);

  ret = malloc(sz);
  MALLOC_CHECK_ASSERT(ret);
  if (!ret) /* just in case */
    return (NULL);

  if (MALLOC_CHECK_TRACE)
    fprintf(stderr, "mc_make(%zu, %s, %u, %s) = %p\n", sz, file,line,func, ret);

  if (MALLOC_CHECK_API_M_SCRUB)
    MALLOC_CHECK_SCRUB_PTR(ret, sz);

  MALLOC_CHECK_STORE.mem_vals[MALLOC_CHECK_STORE.mem_num - 1].ptr  = ret;
  MALLOC_CHECK_STORE.mem_vals[MALLOC_CHECK_STORE.mem_num - 1].sz   = sz;
  MALLOC_CHECK_STORE.mem_vals[MALLOC_CHECK_STORE.mem_num - 1].file = file;
  MALLOC_CHECK_STORE.mem_vals[MALLOC_CHECK_STORE.mem_num - 1].line = line;
  MALLOC_CHECK_STORE.mem_vals[MALLOC_CHECK_STORE.mem_num - 1].func = func;

  return (ret);
}

static void *malloc_check_calloc(size_t num, size_t sz,
                                 const char *file, unsigned int line,
                                 const char *func)
{
  size_t real_sz = num * sz;
  void *ret = NULL;
  
  if ((num != 0) && ((real_sz / sz) != num))
    return (NULL);
  if (!(ret = malloc_check_malloc(real_sz, file, line, func)))
    return (NULL);

  memset(ret, 0, real_sz);
  return (ret);
}

static void malloc_check_free(void *ptr, const char *file, unsigned int line,
                              const char *func)
{
  if (MALLOC_CHECK_TRACE)
    fprintf(stderr, "mc_free(%s, %u, %s, %p)\n", file, line, func, ptr);
  
  if (ptr)
  {
    unsigned int scan = malloc_check_mem(ptr, file, line, func);
    size_t sz = 0;
    
    malloc_check_assert(MALLOC_CHECK_STORE.mem_num > 0);
    --MALLOC_CHECK_STORE.mem_num;

    sz = MALLOC_CHECK_STORE.mem_vals[scan].sz;
    if (scan != MALLOC_CHECK_STORE.mem_num)
    {
      unsigned int num = MALLOC_CHECK_STORE.mem_num;
      Malloc_check_vals *val1 = &MALLOC_CHECK_STORE.mem_vals[scan];
      Malloc_check_vals *val2 = &MALLOC_CHECK_STORE.mem_vals[num];
      
      MALLOC_CHECK_SWAP_TYPE(val1->ptr,  val2->ptr,  void *);
      MALLOC_CHECK_SWAP_TYPE(val1->sz,   val2->sz,   size_t);
      MALLOC_CHECK_SWAP_TYPE(val1->file, val2->file, const char *);
      MALLOC_CHECK_SWAP_TYPE(val1->line, val2->line, unsigned int);
      MALLOC_CHECK_SWAP_TYPE(val1->func, val2->func, const char *);
    }
    MALLOC_CHECK_STORE.mem_vals[MALLOC_CHECK_STORE.mem_num].ptr = NULL;

    if (MALLOC_CHECK_API_F_SCRUB)
      MALLOC_CHECK_SCRUB_PTR(ptr, sz);
    
    free(ptr);
  }
}

static void *malloc_check_realloc(void *ptr, size_t sz,
                                  const char *file, unsigned int line,
                                  const char *func)
{
  void *ret = NULL;
  unsigned int scan = malloc_check_mem(ptr, file, line, func);

  MALLOC_CHECK_ASSERT(ptr && sz);

  if (MALLOC_CHECK_API_R_SCRUB)
  {
    if (!(ret = malloc_check_malloc(sz, file, line, func)))
      return (NULL);

    if (sz >= MALLOC_CHECK_STORE.mem_vals[scan].sz)
      sz = MALLOC_CHECK_STORE.mem_vals[scan].sz;
    if (sz)
      memcpy(ret, ptr, sz);
    
    malloc_check_free(ptr, file, line, func);
    
    return (ret);
  }

  if (MALLOC_CHECK_DEC())
    return (NULL);

  ret = realloc(ptr, sz);
  MALLOC_CHECK_ASSERT(ret);
  if (!ret) /* just in case */
    return (NULL);

  if (MALLOC_CHECK_TRACE)
    fprintf(stderr, "mc_realloc(%p, %zu, %s, %u) = %p\n",
            ptr, sz, file, line, ret);
  /* note we can't scrub ... :( */
  MALLOC_CHECK_STORE.mem_vals[scan].ptr  = ret;
  MALLOC_CHECK_STORE.mem_vals[scan].sz   = sz;
  MALLOC_CHECK_STORE.mem_vals[scan].file = file;
  MALLOC_CHECK_STORE.mem_vals[scan].line = line;
  MALLOC_CHECK_STORE.mem_vals[scan].func = func;

  return (ret);
}

static
void malloc_check_empty(const char *file, unsigned int line, const char *func)
{
  if (MALLOC_CHECK_PRINT && MALLOC_CHECK_STORE.mem_num)
  {
    unsigned int scan = 0;

    while (MALLOC_CHECK_STORE.mem_vals[scan].ptr)
    {
      /* NOTE: Using system *printf, so can't use %zu as Solaris is retarded */
      fprintf(stderr," MEM CHECK NOT EMPTY: ptr %p, sz %lu, from %s:%u:%s\n",
              MALLOC_CHECK_STORE.mem_vals[scan].ptr,
              (unsigned long)MALLOC_CHECK_STORE.mem_vals[scan].sz,
              MALLOC_CHECK_STORE.mem_vals[scan].func,
              MALLOC_CHECK_STORE.mem_vals[scan].line,
              MALLOC_CHECK_STORE.mem_vals[scan].file);
      ++scan;
    }
  }
  malloc_check_assert(!MALLOC_CHECK_STORE.mem_num);
}
#endif

#endif
