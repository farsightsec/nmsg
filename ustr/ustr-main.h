/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_MAIN_H
#define USTR_MAIN_H 1

/* This header file is a few functions for a "simple string" ADT. The idea is
 * that it's so simple you can just copy this header into your project and go.
 * There are extra functions in various ustr-*.h files
 * If you require more, see Vstr etc. */

/* ---- BEG: always static config. ---- */

#ifndef USTR_CONF_HAVE_STDINT_H
#define USTR_CONF_HAVE_STDINT_H 0
#endif

#include <stdlib.h> /* size_t */
#include <string.h> /* strlen() / etc. */
#if USTR_CONF_HAVE_STDINT_H
# include <stdint.h> /* SIZE_MAX */
# define USTR__SIZE_MAX SIZE_MAX
#else
# define USTR__SIZE_MAX ((size_t)-1)
#endif
#include <limits.h> /* CHAR_BIT */

#include <stdarg.h> /* va_list for *printf like functionality,
                     * needed globally now due to cntl and concat */
#include <stdio.h>  /* vsnprintf */

#define USTR_FALSE 0
#define USTR_TRUE  1
#define USTR_NULL  ((struct Ustr *) 0)
#define USTRP_NULL ((struct Ustrp *)0)
#define USTR_POOL_NULL ((struct Ustr_pool *)0)

#ifndef USTR_CONF_USE_ASSERT /* Really defined in ustr-conf.h */
#define USTR_CONF_USE_ASSERT 0
#endif

#if !defined(ustr_assert)     || !defined(USTR_ASSERT) || \
    !defined(ustr_assert_ret) || !defined(USTR_ASSERT_RET)

# undef  ustr_assert
# undef  USTR_ASSERT
# undef  ustr_assert_ret
# undef  USTR_ASSERT_RET

# if USTR_CONF_USE_ASSERT
#  include <assert.h>

#  define ustr_assert(x)        assert(x)
#  define USTR_ASSERT(x)        assert(x)
#  define ustr_assert_ret(x, y) assert(x)
#  define USTR_ASSERT_RET(x, y) assert(x)
# else
#  define ustr_assert(x) /* nothing */
#  define USTR_ASSERT(x) /* nothing */
#  define ustr_assert_ret(x, y)                                 \
    do { if (x){} else return (y); } while (USTR_FALSE)
#  define USTR_ASSERT_RET(x, y)                                 \
    do { if (x){} else return (y); } while (USTR_FALSE)
# endif
#endif

#undef USTR_ASSERT_NO_SWITCH_DEF
#if USTR_CONF_USE_ASSERT
#define USTR_ASSERT_NO_SWITCH_DEF(x) break; default: USTR_ASSERT(! "" x)
#else
#define USTR_ASSERT_NO_SWITCH_DEF(x) break
#endif

#ifndef USTR_CONF_USE_EOS_MARK /* include an "end of string" mark */
#define USTR_CONF_USE_EOS_MARK 0
#endif

#ifndef USTR_CONF_COMPILE_TYPEDEF /* include a typedef for Ustr */
#define USTR_CONF_COMPILE_TYPEDEF 1
#endif

#ifndef USTR_CONF_INCLUDE_CODEONLY_HEADERS /* include headers which are .c's */
#define USTR_CONF_INCLUDE_CODEONLY_HEADERS 1
#endif

#ifndef USTR_CONF_INCLUDE_INTERNAL_HEADERS /* internal functions */
# if USTR_CONF_INCLUDE_CODEONLY_HEADERS
#define USTR_CONF_INCLUDE_INTERNAL_HEADERS 1
#else
#define USTR_CONF_INCLUDE_INTERNAL_HEADERS 0
#endif
#endif

#ifndef USTR_CONF_COMPILE_USE_ATTRIBUTES /* GCC attributes, for speed/warns */
#define USTR_CONF_COMPILE_USE_ATTRIBUTES 1
#endif

#ifndef USTR_CONF_COMPILE_USE_INLINE /* have very small functions inline? */
#define USTR_CONF_COMPILE_USE_INLINE 1
#endif

#include "ustr-compiler.h"

#ifndef USTR_CONF_USE_DYNAMIC_CONF /* make some _CONF settings into variables */
# if ! USTR_CONF_INCLUDE_CODEONLY_HEADERS && USTR_CONF_HAVE_DYNAMIC_CONF
#define USTR_CONF_USE_DYNAMIC_CONF 1
# else
#define USTR_CONF_USE_DYNAMIC_CONF 0
# endif
#endif
/* ---- END: always static config. ---- */

#if USTR_CONF_USE_DYNAMIC_CONF
# if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) ||      \
    (defined(__GNUC__) && (__GNUC__ > 3) && !defined(__STRICT_ANSI__))
#  define USTR_CNTL_MALLOC_CHECK_BEG(x) ((x) ?                          \
   ustr_cntl_opt(666, 0x0FF0, __FILE__, (unsigned int)__LINE__, __func__) : \
   USTR_FALSE)
# else
#  define USTR_CNTL_MALLOC_CHECK_BEG(x) ((x) ?                          \
   ustr_cntl_opt(666, 0x0FF0, __FILE__, (unsigned int)__LINE__, "") :   \
   USTR_FALSE)
# endif
# define USTR_CNTL_MALLOC_CHECK_LVL()           ustr_cntl_opt(666, 0x0FFE)
# define USTR_CNTL_MALLOC_CHECK_MEM(x)          ustr_cntl_opt(666, 0x0FF1, x)
# define USTR_CNTL_MALLOC_CHECK_MEM_SZ(x, y)    ustr_cntl_opt(666, 0x0FF2, x, y)
# define USTR_CNTL_MALLOC_CHECK_MEM_MINSZ(x, y) ustr_cntl_opt(666, 0x0FF3, x, y)
# define USTR_CNTL_MALLOC_CHECK_MEM_USTR(s1) (!ustr_alloc(s1) ||        \
    USTR_CNTL_MALLOC_CHECK_MEM_SZ(s1, ustr_size_alloc(s1)))
# define USTR_CNTL_MALLOC_CHECK_MEM_USTRP(sp1) (!ustrp_alloc(sp1) ||    \
    USTR_CNTL_MALLOC_CHECK_MEM_MINSZ(sp1, ustrp_size_alloc(sp1)))

# if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) ||      \
    (defined(__GNUC__) && (__GNUC__ > 3) && !defined(__STRICT_ANSI__))
# define USTR_CNTL_MALLOC_CHECK_END()                                   \
    ustr_cntl_opt(666, 0x0FFF, __FILE__, (unsigned int)__LINE__, __func__)
# else
# define USTR_CNTL_MALLOC_CHECK_END()                                   \
    ustr_cntl_opt(666, 0x0FFF, __FILE__, (unsigned int)__LINE__, "")
# endif

# define USTR_CNTL_MALLOC_CHECK_ADD(x)                                  \
    (((x) && USTR_CNTL_MALLOC_CHECK_LVL())     ?                        \
     USTR_CNTL_MALLOC_CHECK_BEG(USTR_TRUE) : USTR_FALSE)
# define USTR_CNTL_MALLOC_CHECK_DEL(x)                                  \
    (((x) && USTR_CNTL_MALLOC_CHECK_LVL() > 1) ?                        \
     USTR_CNTL_MALLOC_CHECK_END() : USTR_FALSE)

# define USTR__CNTL_MALLOC_CHECK_FIXUP_REALLOC(x, y)    \
    (void) ustr_cntl_opt(666, 0x0FF4, x, y)

# include "ustr-cntl.h"
#else
# define USTR_CNTL_MALLOC_CHECK_BEG(USTR_TRUE)  (USTR_FALSE)
# define USTR_CNTL_MALLOC_CHECK_LVL()           (0)
# define USTR_CNTL_MALLOC_CHECK_MEM(x)          (USTR_TRUE) /* pretend */
# define USTR_CNTL_MALLOC_CHECK_MEM_SZ(x, y)    (USTR_TRUE) /* pretend */
# define USTR_CNTL_MALLOC_CHECK_MEM_MINSZ(x, y) (USTR_TRUE) /* pretend */
# define USTR_CNTL_MALLOC_CHECK_MEM_USTR(s1)    (USTR_TRUE) /* pretend */
# define USTR_CNTL_MALLOC_CHECK_MEM_USTRP(s1)   (USTR_TRUE) /* pretend */
# define USTR_CNTL_MALLOC_CHECK_END(x)          (USTR_TRUE)
# define USTR_CNTL_MALLOC_CHECK_ADD(x)          (USTR_FALSE)
# define USTR_CNTL_MALLOC_CHECK_DEL(x)          (USTR_TRUE)

# define USTR__CNTL_MALLOC_CHECK_FIXUP_REALLOC(x, y) /* do nothing */
#endif

/* ---- BEG: static/dynamic config. ---- */
/* NOTE: If you alter this it's copied into ustr-cntl-code.c */
#ifndef USTR_CONF_REF_BYTES /* how many bytes to use for reference count */
#define USTR_CONF_REF_BYTES 1
#endif

#ifndef USTR_CONF_HAS_SIZE /* Include a size value */
#define USTR_CONF_HAS_SIZE USTR_FALSE
#endif

#ifndef USTR_CONF_EXACT_BYTES /* don't get a little extra space from malloc() */
#define USTR_CONF_EXACT_BYTES USTR_FALSE
#endif

/* so you can use something else, if you want */
#ifndef USTR_CONF_MALLOC
#define USTR_CONF_MALLOC(x)     malloc(x)
#endif
#ifndef USTR_CONF_REALLOC
#define USTR_CONF_REALLOC(x, y) realloc((x), (y))
#endif
#ifndef USTR_CONF_FREE
#define USTR_CONF_FREE(x)       free(x)
#endif
#ifndef USTR_CONF_VSNPRINTF_BEG
#define USTR_CONF_VSNPRINTF_BEG vsnprintf
#endif
#ifndef USTR_CONF_VSNPRINTF_END
#define USTR_CONF_VSNPRINTF_END vsnprintf
#endif
/* ---- END: static/dynamic config. ---- */


#define USTR__COMPILE_ASSERT(x, y)                \
    extern char ustr__compiler_assert_ ## y[1 - 2*!(x)]

USTR__COMPILE_ASSERT(CHAR_BIT == 8, num_char_bits);

#if USTR_CONF_HAVE_64bit_SIZE_MAX
USTR__COMPILE_ASSERT(USTR__SIZE_MAX >= 0xFFFFFFFFFFFFFFFFULL,
                     small_size_t_limit64);
#else
USTR__COMPILE_ASSERT(USTR__SIZE_MAX >= 0xFFFFFFFFUL, small_size_t_limit32);
#endif

#if ! USTR_CONF_USE_DYNAMIC_CONF
# if !((USTR_CONF_REF_BYTES == 0) || (USTR_CONF_REF_BYTES == 1) || \
       (USTR_CONF_REF_BYTES == 2) || (USTR_CONF_REF_BYTES == 4) || \
       (USTR_CONF_HAVE_64bit_SIZE_MAX && (USTR_CONF_REF_BYTES == 8)))
#  error "Bad size for USTR_CONF_REF_BYTES"
# endif
#endif


/* As the saying goes:
 *   "you can tell a lot about the code from the data structure".
 *
 * So this is the non-magic version of the struct Ustr:
 *
 * struct Ustr
 * {
 *   const char *ptr;
 *   size_t reference_count;
 *   size_t length;
 *   size_t size;
 *
 *   unsigned char flag_is_readonly            : 1;
 *   unsigned char flag_is_fixed               : 1;
 *   unsigned char flag_exact_byte_allocations : 1;
 *   unsigned char flag_has_enomem_error       : 1;
 *   unsigned char flag_fail_on_alloc          : 1;
 * };
 *
 * ...however this "eats" memory for "small" strings, which is one reason given
 * why people don't use a real string ADT.
 *
 */
struct Ustr 
{
 unsigned char data[1];
 /* 0b_wxyz_nnoo =>
  * 
  *    w         = allocated
  *     x        = has size
  *      y       = round up allocations (off == exact allocations)
  *       z      = memory error
  *         nn   = refn
  *           oo = lenn
  *
  * Eg.
  *
  * 0b_0000_0000 ==
  *           "" ==
  * not allocated, [no size], [no round up allocs], no mem err, refn=0, lenn=0
  *
  * 0b1000_0001 ==
  *        0xA5 ==
  * allocated, no size, no round up allocs,         no mem err, refn=0, lenn=1
  *
  * 0b1010_0101 ==
  *        0xA5 ==
  * allocated, no size,    round up allocs,         no mem err, refn=1, lenn=1
  */
};
struct Ustrp
{ /* This is a type for the "pool" allocated Ustr it is a seperate type as a
   * way to catch errors at compile time with static typing. You might think
   * we'd define Ustrp to be identical to Ustr, and just cast ... however
   * I'm 99% sure that aliasing rules screw us over if we do that. */
  struct Ustr s;
};

/* On ARM sizeof(struct Ustr) == 4, while sizeof("") == 1. Note that all the
 * unit tests pass, so it isn't accessing the padding bytes when you do:
 *
 *   s1->data[0]
 *
 * ...or if it is, it isn't causing problems. Even so, it might be worth
 * fixing this for 2.0? */
USTR__COMPILE_ASSERT(sizeof("") <= sizeof(struct Ustr),  bad_sizeof_ustr);
USTR__COMPILE_ASSERT(sizeof(struct Ustrp) == sizeof(struct Ustr),
                     bad_sizeof_ustrp);
/* Unused bit patterns for data[0]:
 *
 * 0bx0xx_x100 == lenn = 0
 * 0bx0xx_1x00
 * 0bx0x1_xx00
 * 0bx01x_xx00
 *              0bx1xx_xx00 => is used in sized
 * 0b10xx_xx00
 *
 * 0bx1xx_xx11 == 128bit size_t, yeh!
 * 0bx1xx_11xx
 *
 * 0b0xxx_x1xx == refn values for const/fixed
 * 0b0xxx_1xxx
 *
 * 0b00x1_xxxx == mem error for const
 * 0b001x_xxxx == not exact for const
 *
 */
#define USTR__BIT_ALLOCD (1<<7)
#define USTR__BIT_HAS_SZ (1<<6)
#define USTR__BIT_NEXACT (1<<5)
#define USTR__BIT_ENOMEM (1<<4)

#define USTR__BITS_RW      (USTR__BIT_ALLOCD | USTR__BIT_HAS_SZ)
#define USTR__BITS_FIXED                       USTR__BIT_HAS_SZ
#define USTR__BITS_RWLIM   (USTR__BIT_ALLOCD | USTR__BIT_HAS_SZ |       \
                            USTR__BIT_NEXACT)
#define USTR__BITS_LIMITED                     USTR__BIT_HAS_SZ

/* constant string macros */
#define USTR_BEG_CONST1     "\x01"
#define USTR_BEG_CONST2     "\x02"
#define USTR_BEG_CONST4     "\x03"
#define USTR_BEG_RO1        "\x01" /* compat. only */
#define USTR_BEG_RO2        "\x02" /* compat. only */
#define USTR_BEG_RO4        "\x03" /* compat. only */
#define USTR_BEG_FIXED2  "x112233"
#define USTR_BEG_FIXED4  "x1122223333"         /* Likely? */
#if USTR_CONF_HAVE_64bit_SIZE_MAX
# define USTR_BEG_FIXED8 "x112222222233333333" /* Not, so much. */
#endif
#if USTR_CONF_USE_EOS_MARK /* i == 0b_0110_1001 */
# define USTR_END_CONSTx "\0<ii-CONST_EOS-ii>"
# define USTR_END_ALOCDx "\0<ii-ALOCD_EOS-ii>"
# define USTR_END_FIXEDx "\0<ii-FIXED_EOS-ii>"
#else
# define USTR_END_CONSTx ""
# define USTR_END_ALOCDx ""
# define USTR_END_FIXEDx ""
#endif
USTR__COMPILE_ASSERT((sizeof(USTR_END_CONSTx) == sizeof(USTR_END_ALOCDx)),
                     eos_alloced_bad_size);
USTR__COMPILE_ASSERT((sizeof(USTR_END_CONSTx) == sizeof(USTR_END_FIXEDx)),
                     eos_fixed_bad_size);
  

#define USTR(x)  ((struct Ustr  *) x)
#define USTRP(x) ((struct Ustrp *) x)

#define USTR1(x1, y)                                                    \
    USTR(USTR_BEG_CONST1 #x1                             y USTR_END_CONSTx)
#define USTR2(x1, x2, y)                                                \
    USTR(USTR_BEG_CONST2 #x2 #x1                         y USTR_END_CONSTx)
#define USTR4(x1, x2, x3, x4, y)                                        \
    USTR(USTR_BEG_CONST4 #x4 #x3 #x2 #x1                 y USTR_END_CONSTx)

#define USTRP1(x1, y)                                                   \
    USTRP(USTR_BEG_CONST1 #x1                             y USTR_END_CONSTx)
#define USTRP2(x1, x2, y)                                               \
    USTRP(USTR_BEG_CONST2 #x2 #x1                         y USTR_END_CONSTx)
#define USTRP4(x1, x2, x3, x4, y)                                       \
    USTRP(USTR_BEG_CONST4 #x4 #x3 #x2 #x1                 y USTR_END_CONSTx)

#define USTR1_CHK(x1, y) ((*( #x1 ) == (sizeof(y) - 1)) ?               \
    USTR(USTR_BEG_CONST1 #x1                              y USTR_END_CONSTx) : \
    USTR(""))
#define USTR2_CHK(x1, x2, y)                                            \
    ((((size_t)*( #x1 ) * 256 + *( #x2 )) == (sizeof(y) - 1)) ?         \
    USTR(USTR_BEG_CONST2 #x2 #x1                          y USTR_END_CONSTx) : \
    USTR(""))
#define USTR4_CHK(x1, x2, x3, x4, y)                                    \
    ((((size_t)*( #x1 ) * 16777216 + (size_t)*( #x2 ) * 65536 +         \
       (size_t)*( #x3 ) * 256      + *( #x4 )) == (sizeof(y) - 1)) ?    \
    USTR(USTR_BEG_CONST4 #x4 #x3 #x2 #x1                  y USTR_END_CONSTx) : \
    USTR(""))

#define USTRP1_CHK(x1, y) ((*( #x1 ) == (sizeof(y) - 1)) ?              \
    USTRP(USTR_BEG_CONST1 #x1                             y USTR_END_CONSTx) : \
    USTRP(""))
#define USTRP2_CHK(x1, x2, y)                                           \
    ((((size_t)*( #x1 ) * 256 + *( #x2 )) == (sizeof(y) - 1)) ?         \
    USTRP(USTR_BEG_CONST2 #x2 #x1                         y USTR_END_CONSTx) : \
    USTRP(""))
#define USTRP4_CHK(x1, x2, x3, x4, y)                                   \
    ((((size_t)*( #x1 ) * 16777216 + (size_t)*( #x2 ) * 65536 +         \
       (size_t)*( #x3 ) * 256      + *( #x4 )) == (sizeof(y) - 1)) ?    \
    USTRP(USTR_BEG_CONST4 #x4 #x3 #x2 #x1                 y USTR_END_CONSTx) : \
    USTRP(""))
    

/*
 *    ================ English description of struct Ustr ================
 *
 *  This strucure is very magic, as an optimization "" is a valid "structure"
 * for an empty string, ustr_len("") == 0, ustr_size("") == 0,
 * ustr_cstr("") == "".
 *  This also works for other "static data strings" if they start with the first
 * four bits as 0 ... although for C const strings using this, the length has
 * to be manually defined correctly at compile time.
 *
 *  However it is also a "space efficient" String ADT, with a managed length,
 * _either_ with or without reference counts (so that ustr_dup() doesn't copy)
 * and with or without a stored size (so growing/shrinking a lot doesn't
 * cause lots of malloc/realloc usage). Note that for lengths of strings, or
 * reference counts that need >= 8 bytes of storage the Ustr _MUST_ contain
 * a stored size.
 * 
 *  It can also track memory allocation errors over multiple function calls.
 *
 *  If the first byte == 0, then it's "" as above.
 *  Otherwise the first byte contains four flags, and 2 numbers (2 bits each).
 *
 *  The 1st flag says if the string is allocated. The 2nd flag says if it has a
 * stored size. The 3rd flag says if it isn't using "exact allocations", if it
 * is ustr_len() + ustr_overhead() == ustr_size_alloc(), otherwise there might
 * be room to grow without doing a memory allocation call[1]. The 4th flag says
 * if this Ustr has had a memory allocation error.
 * The two numbers are the mappings for the length of the reference count, and
 * the length of the length. Note that this mapping changes if the 2nd flag is
 * set.
 *
 * [1] There is an implied "size" of the string, based an how big it is. This
 * is a concession for speed efficiency, although it only grows at 1.5x
 * not 2x which is the norm. (again, to reduce memory waste). Again if this is
 * too much overhead, just use exact sized allocations.
 *
 *  Also NOTE if the 1st and 2nd flags are set, this means that the Ustr is in
 * fixed storge (like an auto array). Also if the 1st, 2nd and 3rd flags are
 * set, this means that the Ustr is limited, Ie. it's in fixed storge and
 * _CANNOT_ grow (all allocation attempts will fail).
 *
 *  == If there is any more data after the above declared one they have
 *     been allocated via. the "struct hack" method (search for more info). ==
 *
 *  Next, possibly, comes the reference count (of the given length[2]).
 *  Next, if not "", comes the length of the data (of the given length[2]).
 *  Next, if non-zero length, comes the data, which can include NIL bytes.
 *  And finally, if not "", a NIL byte, to make sure it's always a valid C-Style
 * string (although obviously any embeded NIL bytes will make it look shorter
 * if something else just uses strlen(ustr_cstr())).
 *
 * [2] The sizes can currently be 1, 2, 4 or 8 bytes. Depending on the mapping
 * of the value in the first byte (length changes dynamically, as you add data).
 *
 *  Examples:
 *
 *  The allocated string "a", using exact allocations and no reference
 * counting, is the 4 bytes:
 *
 *     {0x81, 0x01, 'a', 0x00}
 *
 *
 *  The allocated string "ab", using non-exact allocations and 1 byte reference
 * counting (shared by 13 users), is the 6 bytes (there is no waste due to
 * non-exact allocations):
 *
 *     {0xA5, 0x0D, 0x02, 'a', 'b', 0x00}
 *
 *
 *  The allocated string "abcdefghijklmnop" (16 bytes, and a NIL), with
 * non-exact allocations 2 byte reference counting (shared by 1,003 users), is
 * the 24 bytes (with 3 bytes of "unused" space at the end):
 *
 *     {0xA9, 0x03, 0xEB, 0x10, 'a', 'b', [...], 'o', 'p', 0x00, <x>, <x>, <x>}
 */

struct Ustr_pool
{
 void *(*pool_sys_malloc)(struct Ustr_pool *, size_t);
 void *(*pool_sys_realloc)(struct Ustr_pool *, void *, size_t, size_t);
 void  (*pool_sys_free)(struct Ustr_pool *, void *);
 
 struct Ustr_pool *(*pool_make_subpool)(struct Ustr_pool *);
 void  (*pool_clear)(struct Ustr_pool *);
 void  (*pool_free)(struct Ustr_pool *);
};

#if USTR_CONF_COMPILE_TYPEDEF
typedef struct Ustr      Ustr;
typedef struct Ustrp     Ustrp;
typedef struct Ustr_pool Ustr_pool;
#endif

#define USTR_SC_INIT_AUTO(x, y, z)              \
    ustr_init_fixed(x, sizeof(x), y, z)
#define USTR_SC_INIT_AUTO_OSTR(x, y, z)              \
    ustr_init_fixed(x, sizeof(x), y, sizeof(z) - 1)

#define USTRP_SC_INIT_AUTO(x, y, z)             \
    ustrp_init_fixed(x, sizeof(x), y, z)
#define USTRP_SC_INIT_AUTO_OSTR(x, y, z)             \
    ustrp_init_fixed(x, sizeof(x), y, sizeof(z) - 1)

/* (x) && (((x) - 1) >= 0xFFFFFFFF) should really be:
   (x) > 0xFFFFFFFF ... but GCC likes to warn about that if x == 4, say */
#define USTR_SIZE_FIXED(x) ((x) + 1 + 2 + 4 +                           \
                            (((x) > 0xFFFF)     ? 4 : 0) +              \
                            ((USTR_CONF_HAVE_64bit_SIZE_MAX && (x) &&   \
                              (((x) - 1) >= 0xFFFFFFFF)) ? 8 : 0) +     \
                            sizeof(USTR_END_FIXEDx))

#define USTR_ADD_OBJ(x, y)  ustr_add_buf(x, y, sizeof(y))
#define USTR_ADD_OSTR(x, y) ustr_add_buf(x, y, sizeof(y) - 1)
#define USTR_DUP_OBJ(y)     ustr_dup_buf(y, sizeof(y))
#define USTR_DUP_OSTR(y)    ustr_dup_buf(y, sizeof(y) - 1)
#define USTR_DUPX_OBJ(x1, x2, x3, x4, y)        \
    ustr_dupx_buf(x1, x2, x3, x4, y, sizeof(y))
#define USTR_DUPX_OSTR(x1, x2, x3, x4, y)        \
    ustr_dupx_buf(x1, x2, x3, x4, y, sizeof(y) - 1)

#define USTRP_ADD_OBJ(p, x, y)  ustrp_add_buf(p, x, y, sizeof(y))
#define USTRP_ADD_OSTR(p, x, y) ustrp_add_buf(p, x, y, sizeof(y) - 1)
#define USTRP_DUP_OBJ(p, y)     ustrp_dup_buf(p, y, sizeof(y))
#define USTRP_DUP_OSTR(p, y)    ustrp_dup_buf(p, y, sizeof(y) - 1)
#define USTRP_DUPX_OBJ(p, x1, x2, x3, x4, y)        \
    ustrp_dupx_buf(p, x1, x2, x3, x4, y, sizeof(y))
#define USTRP_DUPX_OSTR(p, x1, x2, x3, x4, y)        \
    ustrp_dupx_buf(p, x1, x2, x3, x4, y, sizeof(y) - 1)

#define USTR__REF_LEN(x)     ustr_xi__pow2(ustr_sized(x), (x)->data[0] >> 2)
#define USTR__LEN_LEN(x)     ustr_xi__pow2(ustr_sized(x), (x)->data[0])

/* ---------------- Ustr "pool" because none in stdlib. ---------------- */

USTR_CONF_EI_PROTO struct Ustr_pool *ustr_pool_make_subpool(struct Ustr_pool *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_MALLOC()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO void ustr_pool_clear(struct Ustr_pool *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO void ustr_pool_free(struct Ustr_pool *);

/* This converts a number n to 2**(n-1) -- for small values > 0.
 * Where  n==0 means 0.
 * Oh and n==7 means 0 -- because, see above. */
USTR_CONF_EI_PROTO size_t ustr_xi__pow2(int, unsigned char)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_CONST();

/* Check if everything looks OK, should be used in debugging only. */
USTR_CONF_E_PROTO int ustr_assert_valid(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_assert_valid_subustr(const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO int ustrp_assert_valid(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
int ustrp_assert_valid_subustrp(const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO size_t ustr_xi__embed_val_get(const unsigned char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO size_t ustr_xi__ref_get(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

/* ---------------- Ustr "member" access ---------------- */
USTR_CONF_EI_PROTO size_t ustr_len(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO const char *ustr_cstr(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO char *ustr_wstr(struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO int ustr_alloc(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_exact(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_sized(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_ro(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_fixed(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_enomem(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_shared(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_limited(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO  int ustr_owner(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
void ustr_conf(const struct Ustr *, size_t *,size_t *,int *, size_t *,size_t *)
    USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_E_PROTO int ustr_setf_enomem_err(struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */
USTR_CONF_E_PROTO int ustr_setf_enomem_clr(struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */

USTR_CONF_E_PROTO int ustr_setf_share(struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */
USTR_CONF_E_PROTO int ustr_setf_owner(struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */

USTR_CONF_E_PROTO size_t ustr_size(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO size_t ustr_size_alloc(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO size_t ustr_size_overhead(const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

/* ---------------- free Ustr's ---------------- */

USTR_CONF_E_PROTO void ustrp_free(struct Ustr_pool *, struct Ustrp *);

USTR_CONF_E_PROTO void ustr_free(struct Ustr *);

/* ---------------- init - helpers so others can make Ustr's ---------------- */
USTR_CONF_E_PROTO size_t ustr_init_size(size_t, size_t, int, size_t)
    USTR__COMPILE_ATTR_CONST() USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_E_PROTO
struct Ustr *ustr_init_alloc(void *, size_t, size_t, size_t, int, int, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
struct Ustr *ustr_init_fixed(void *, size_t, int, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
struct Ustrp *ustrp_init_alloc(void *, size_t, size_t, size_t, int, int, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
struct Ustrp *ustrp_init_fixed(void *, size_t, int, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

/* ---------------- add ---------------- */

USTR_CONF_E_PROTO int ustr_add_undef(struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
int ustrp_add_undef(struct Ustr_pool *, struct Ustrp **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

USTR_CONF_E_PROTO int ustr_add_buf(struct Ustr **, const void *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_add_cstr(struct Ustr **, const char *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_add(struct Ustr **, const struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
int ustr_add_subustr(struct Ustr **, const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_add_rep_chr(struct Ustr **, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
int ustrp_add_buf(struct Ustr_pool *, struct Ustrp **, const void *, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_EI_PROTO
int ustrp_add_cstr(struct Ustr_pool *, struct Ustrp **, const char *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_add(struct Ustr_pool *, struct Ustrp **, const struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO int ustrp_add_subustrp(struct Ustr_pool *, struct Ustrp **,
                                         const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_add_rep_chr(struct Ustr_pool *, struct Ustrp **, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

/* ---------------- del ---------------- */

USTR_CONF_E_PROTO int ustr_realloc(struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO int ustrp_realloc(struct Ustr_pool *, struct Ustrp **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

USTR_CONF_E_PROTO int ustr_del(struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_del_subustr(struct Ustr **, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO int ustrp_del(struct Ustr_pool *, struct Ustrp **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO
int ustrp_del_subustrp(struct Ustr_pool *, struct Ustrp **, size_t,size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

/* ---------------- dup ---------------- */

USTR_CONF_E_PROTO struct Ustr *ustr_dupx_undef(size_t, size_t, int, int, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_undef(struct Ustr_pool *, size_t, size_t, int, int,
                               size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_E_PROTO struct Ustr *ustr_dup_undef(size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_E_PROTO struct Ustrp *ustrp_dup_undef(struct Ustr_pool *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_E_PROTO struct Ustr *ustr_dupx_empty(size_t, size_t, int, int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_empty(struct Ustr_pool *, size_t, size_t, int, int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_E_PROTO struct Ustr *ustr_dup_empty(void)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_E_PROTO struct Ustrp *ustrp_dup_empty(struct Ustr_pool *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_E_PROTO
struct Ustr *ustr_dupx_buf(size_t, size_t, int, int, const void *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO struct Ustr *ustr_dup_buf(const void *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
struct Ustr *ustr_dupx_cstr(size_t, size_t, int, int, const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO struct Ustr *ustr_dup_cstr(const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
struct Ustr *ustr_dupx(size_t, size_t, int, int, const struct Ustr *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO struct Ustr *ustr_dup(const struct Ustr *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
struct Ustr *
ustr_dupx_subustr(size_t, size_t, int, int, const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
struct Ustr *ustr_dup_subustr(const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
struct Ustr *ustr_dupx_rep_chr(size_t, size_t, int, int, char, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_E_PROTO struct Ustr *ustr_dup_rep_chr(char, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_buf(struct Ustr_pool *, size_t, size_t, int, int,
                             const void *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((6));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dup_buf(struct Ustr_pool *, const void *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_EI_PROTO
struct Ustrp *ustrp_dupx_cstr(struct Ustr_pool *, size_t, size_t, int, int,
                              const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((6));
USTR_CONF_EI_PROTO struct Ustrp *ustrp_dup_cstr(struct Ustr_pool *,const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx(struct Ustr_pool *, size_t, size_t, int, int,
                         const struct Ustrp *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((6));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dup(struct Ustr_pool *, const struct Ustrp *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_subustrp(struct Ustr_pool *, size_t, size_t, int, int,
                                  const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((6));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dup_subustrp(struct Ustr_pool *,
                                 const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_rep_chr(struct Ustr_pool *, size_t, size_t, int, int,
                                 char, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();
USTR_CONF_E_PROTO struct Ustrp *ustrp_dup_rep_chr(struct Ustr_pool *,
                                                  char, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET();

/* ---------------- shortcut ---------------- */

USTR_CONF_E_PROTO void ustr_sc_del(struct Ustr **)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO void ustr_sc_free(struct Ustr **)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO void ustr_sc_free2(struct Ustr **, struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO void ustrp_sc_del(struct Ustr_pool *, struct Ustrp **)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO void ustrp_sc_free(struct Ustr_pool *, struct Ustrp **)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO
void ustrp_sc_free2(struct Ustr_pool *, struct Ustrp **, struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));


USTR_CONF_E_PROTO int ustr_sc_ensure_owner(struct Ustr **)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO char *ustr_sc_wstr(struct Ustr **)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO int ustrp_sc_ensure_owner(struct Ustr_pool *, struct Ustrp **)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO char *ustrp_sc_wstr(struct Ustr_pool *, struct Ustrp **)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2));

/* ---------------- pre inlines ---------------- */
#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO struct Ustr_pool *ustr_pool_make_subpool(struct Ustr_pool *p)
{
  USTR_ASSERT(p);
  return (p->pool_make_subpool(p));
}
USTR_CONF_II_PROTO void ustr_pool_clear(struct Ustr_pool *p)
{
  USTR_ASSERT(p);
  p->pool_clear(p);
}
USTR_CONF_II_PROTO void ustr_pool_free(struct Ustr_pool *p)
{
  if (!p)
    return;

  p->pool_free(p);
}

USTR_CONF_II_PROTO int ustr_alloc(const struct Ustr *s1)
{ return (!!(s1->data[0] & USTR__BIT_ALLOCD)); }
USTR_CONF_II_PROTO int ustr_exact(const struct Ustr *s1)
{ return ( !(s1->data[0] & USTR__BIT_NEXACT)); }
USTR_CONF_II_PROTO int ustr_sized(const struct Ustr *s1)
{ return (!!(s1->data[0] & USTR__BIT_HAS_SZ)); }
USTR_CONF_II_PROTO int ustr_enomem(const struct Ustr *s1)
{ return (!!(s1->data[0] & USTR__BIT_ENOMEM)); }

/* these are compound bit tests */
USTR_CONF_II_PROTO int ustr_ro(const struct Ustr *s1)
{ return (!(s1->data[0] & USTR__BITS_RW)); }
USTR_CONF_II_PROTO int ustr_fixed(const struct Ustr *s1)
{ return (( s1->data[0] & USTR__BITS_RW) == USTR__BITS_FIXED); }
USTR_CONF_II_PROTO int ustr_limited(const struct Ustr *s1)
{ return (( s1->data[0] & USTR__BITS_RWLIM) == USTR__BITS_LIMITED); }

USTR_CONF_II_PROTO
size_t ustr_xi__embed_val_get(const unsigned char *data, size_t len)
{
  size_t ret = 0;
  
  switch (len)
  {
    case 0: return (-1);

#if USTR_CONF_HAVE_64bit_SIZE_MAX
    case 8:
      ret |= (((size_t)data[7]) << 56);
      ret |= (((size_t)data[6]) << 48);
      ret |= (((size_t)data[5]) << 40);
      ret |= (((size_t)data[4]) << 32);
#endif
    case 4:
      ret |= (((size_t)data[3]) << 24);
      ret |= (((size_t)data[2]) << 16);
    case 2:
      ret |= (((size_t)data[1]) <<  8);
    case 1:
      ret |= (((size_t)data[0]) <<  0);
   
      USTR_ASSERT_NO_SWITCH_DEF("Val. length bad for ustr_xi__embed_val_get()");
  }

  return (ret);
}

USTR_CONF_II_PROTO size_t ustr_xi__pow2(int use_big, unsigned char len)
{ /* FIXME: for 2.0 or whatever make this something like:
     static const unsigned char map_pow2[4] = {0, 1, 2, sizeof(size_t)};
   */
  static const unsigned char map_big_pow2[4] = {2, 4, 8, 16};
  static const unsigned char map_pow2[4] = {0, 1, 2,  4};
  
  if (use_big)
    return (map_big_pow2[len & 0x03]);
  
  return (map_pow2[len & 0x03]);
}
USTR_CONF_II_PROTO size_t ustr_xi__ref_get(const struct Ustr *s1)
{ return (ustr_xi__embed_val_get(s1->data + 1, USTR__REF_LEN(s1))); }
USTR_CONF_II_PROTO int ustr_shared(const struct Ustr *s1)
{ return (ustr_ro(s1) || (ustr_alloc(s1) && !ustr_xi__ref_get(s1))); }

USTR_CONF_II_PROTO size_t ustr_len(const struct Ustr *s1)
{ /* NOTE: can't call ustr_assert_valid() here due to recursion,
   * also because assert_valid() is inline, and defined later on. */
  USTR_ASSERT(s1);
  
  if (!s1->data[0]) return (0);
  
  return (ustr_xi__embed_val_get(s1->data + 1 + USTR__REF_LEN(s1),
                                 USTR__LEN_LEN(s1)));
}
USTR_CONF_II_PROTO const char *ustr_cstr(const struct Ustr *s1)
{ /* NOTE: can't call ustr_assert_valid() here due to recursion,
   * also because assert_valid() is inline, and defined later on. */
  size_t lenn = 0;

  USTR_ASSERT(s1);
  
  if (!s1->data[0]) return ((const char *)s1->data);

  lenn = USTR__LEN_LEN(s1);
  if (ustr_sized(s1))
    lenn *= 2;
  
  return ((const char *)(s1->data + 1 + USTR__REF_LEN(s1) + lenn));
}
#endif

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-main-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-main-code.h"
#endif

/* ---------------- post inlines ---------------- */
#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
int ustrp_add_cstr(struct Ustr_pool *p, struct Ustrp **ps1, const char *cstr)
{ return (ustrp_add_buf(p, ps1, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO int ustr_add_cstr(struct Ustr **ps1, const char *cstr)
{ return (ustr_add_buf(ps1, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
struct Ustrp *ustrp_dupx_cstr(struct Ustr_pool *p, size_t sz, size_t rb,
                              int ex, int me, const char *c)
{ return (ustrp_dupx_buf(p, sz, rb, ex, me, c, strlen(c))); }
USTR_CONF_II_PROTO
struct Ustrp *ustrp_dup_cstr(struct Ustr_pool *p, const char *cstr)
{ return (ustrp_dup_buf(p, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
struct Ustr *ustr_dupx_cstr(size_t sz, size_t rb, int ex, int me, const char *c)
{ return (ustr_dupx_buf(sz, rb, ex, me, c, strlen(c))); }
USTR_CONF_II_PROTO struct Ustr *ustr_dup_cstr(const char *cstr)
{ return (ustr_dup_buf(cstr, strlen(cstr))); }
#endif

/* ---------------- pool wrapper APIs ---------------- */
USTR_CONF_EI_PROTO size_t ustrp_len(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO const char *ustrp_cstr(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO char *ustrp_wstr(struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO int ustrp_alloc(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_exact(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_sized(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_ro(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_fixed(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_enomem(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_shared(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_limited(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustrp_owner(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
void ustrp_conf(const struct Ustrp*, size_t *,size_t *,int *, size_t *,size_t *)
    USTR__COMPILE_ATTR_NONNULL_L((1));

USTR_CONF_EI_PROTO int ustrp_setf_enomem_err(struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */
USTR_CONF_EI_PROTO int ustrp_setf_enomem_clr(struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */

USTR_CONF_EI_PROTO int ustrp_setf_share(struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */
USTR_CONF_EI_PROTO int ustrp_setf_owner(struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_A(); /* _can_ ignore the "error return" here */

USTR_CONF_EI_PROTO size_t ustrp_size(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO size_t ustrp_size_alloc(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO size_t ustrp_size_overhead(const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO size_t ustrp_len(const struct Ustrp *s1)
{ return (ustr_len(&s1->s)); }
USTR_CONF_II_PROTO const char *ustrp_cstr(const struct Ustrp *s1)
{ return (ustr_cstr(&s1->s)); }
USTR_CONF_II_PROTO char *ustrp_wstr(struct Ustrp *s1)
{ return (ustr_wstr(&s1->s)); }

USTR_CONF_II_PROTO int ustrp_alloc(const struct Ustrp *s1)
{ return (ustr_alloc(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_exact(const struct Ustrp *s1)
{ return (ustr_exact(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_sized(const struct Ustrp *s1)
{ return (ustr_sized(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_ro(const struct Ustrp *s1)
{ return (ustr_ro(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_fixed(const struct Ustrp *s1)
{ return (ustr_fixed(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_enomem(const struct Ustrp *s1)
{ return (ustr_enomem(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_shared(const struct Ustrp *s1)
{ return (ustr_shared(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_limited(const struct Ustrp *s1)
{ return (ustr_limited(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_owner(const struct Ustrp *s1)
{ return (ustr_owner(&s1->s)); }
USTR_CONF_II_PROTO
void ustrp_conf(const struct Ustrp *s1, size_t *esz, size_t *ref,
                int *exact, size_t *lenn, size_t *refc)
{ ustr_conf(&s1->s, esz, ref, exact, lenn, refc); }

USTR_CONF_II_PROTO int ustrp_setf_enomem_err(struct Ustrp *s1)
{ return (ustr_setf_enomem_err(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_setf_enomem_clr(struct Ustrp *s1)
{ return (ustr_setf_enomem_clr(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_setf_share(struct Ustrp *s1)
{ return (ustr_setf_share(&s1->s)); }
USTR_CONF_II_PROTO int ustrp_setf_owner(struct Ustrp *s1)
{ return (ustr_setf_owner(&s1->s)); }
USTR_CONF_II_PROTO size_t ustrp_size(const struct Ustrp *s1)
{ return (ustr_size(&s1->s)); }
USTR_CONF_II_PROTO size_t ustrp_size_alloc(const struct Ustrp *s1)
{ return (ustr_size_alloc(&s1->s)); }
USTR_CONF_II_PROTO size_t ustrp_size_overhead(const struct Ustrp *s1)
{ return (ustr_size_overhead(&s1->s)); }
#endif


#endif
