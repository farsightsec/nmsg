/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_MAIN_H
#error " Include ustr.h or ustr-main.h before this file."
#endif

#ifndef USTR_CONF_HAVE_64bit_SIZE_MAX
#define USTR_CONF_HAVE_64bit_SIZE_MAX 0
#endif

#ifndef USTR_CONF_HAVE_ATTR_FMT
#define USTR_CONF_HAVE_ATTR_FMT 1
#endif

/* We assume this is enough,
 * C99 specifies that va_copy() exists and is a macro */
#ifdef va_copy
# define USTR_CONF_HAVE_VA_COPY 1
# define USTR__VA_COPY(x, y)   va_copy(x, y)
#elif __va_copy
# define USTR_CONF_HAVE_VA_COPY 1
# define USTR__VA_COPY(x, y) __va_copy(x, y)
#else
# define USTR_CONF_HAVE_VA_COPY 0
#endif

#ifndef USTR_CONF_HAVE_ATTR_NONNULL
#if defined(__GNUC__) && (__GNUC__ > 3) /* not sure */
#define USTR_CONF_HAVE_ATTR_NONNULL 1
#else
#define USTR_CONF_HAVE_ATTR_NONNULL 0
#endif
#endif

#ifndef USTR_CONF_HAVE_ATTR_PURE
#if defined(__GNUC__) && \
    ((__GNUC__ > 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 96)))
#define USTR_CONF_HAVE_ATTR_PURE 1
#else
#define USTR_CONF_HAVE_ATTR_PURE 0
#endif
#endif

#ifndef USTR_CONF_HAVE_ATTR_CONST
#if defined(__GNUC__) && \
    ((__GNUC__ > 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 5)))
#define USTR_CONF_HAVE_ATTR_CONST 1
#else
#define USTR_CONF_HAVE_ATTR_CONST 0
#endif
#endif

#ifndef USTR_CONF_HAVE_ATTR_MALLOC
#if defined(__GNUC__) && (__GNUC__ > 3) /* not sure */
#define USTR_CONF_HAVE_ATTR_MALLOC 1
#else
#define USTR_CONF_HAVE_ATTR_MALLOC 0
#endif
#endif

#ifndef USTR_CONF_HAVE_ATTR_WARN_UNUSED_RET
#if defined(__GNUC__) && (__GNUC__ > 3) /* not sure */
#define USTR_CONF_HAVE_ATTR_WARN_UNUSED_RET 1
#else
#define USTR_CONF_HAVE_ATTR_WARN_UNUSED_RET 0
#endif
#endif

#ifndef USTR_CONF_HAVE_ATTR_UNUSED
#if defined(__GNUC__) && \
    ((__GNUC__ > 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 96))) /*before? */
#define USTR_CONF_HAVE_ATTR_UNUSED 1
#else
#define USTR_CONF_HAVE_ATTR_UNUSED 0
#endif
#endif

#ifndef USTR_CONF_HAVE_ATTR_DEPRECATED
#if defined(__GNUC__) && (__GNUC__ > 3) /* not sure */
#define USTR_CONF_HAVE_ATTR_DEPRECATED 1
#else
#define USTR_CONF_HAVE_ATTR_DEPRECATED 0
#endif
#endif

#ifndef USTR_CONF_HAVE_ATTR_SENTINEL
#if defined(__GNUC__) && \
    ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 1))) /*before? */
#define USTR_CONF_HAVE_ATTR_SENTINEL 1
#else
#define USTR_CONF_HAVE_ATTR_SENTINEL 0
#endif
#endif

#if USTR_CONF_COMPILE_USE_INLINE
#define USTR__INLINE inline
#else
#define USTR__INLINE /* no inline */
#endif

#ifndef USTR_CONF_E_PROTO /* external */
# if USTR_CONF_INCLUDE_CODEONLY_HEADERS
#  define USTR_CONF_E_PROTO static USTR__INLINE
# else
#  define USTR_CONF_E_PROTO extern
# endif
#endif
#ifndef USTR_CONF_I_PROTO /* implementation */
# if USTR_CONF_INCLUDE_CODEONLY_HEADERS
#  define USTR_CONF_I_PROTO static USTR__INLINE
# else
#  define USTR_CONF_I_PROTO
# endif
#endif

#ifndef USTR_CONF_EI_PROTO /* external inline */
# if USTR_CONF_INCLUDE_CODEONLY_HEADERS
#  define USTR_CONF_EI_PROTO static USTR__INLINE
# else
#  define USTR_CONF_EI_PROTO extern
# endif
#endif
#ifndef USTR_CONF_II_PROTO /* implementation of inline */
# if USTR_CONF_INCLUDE_CODEONLY_HEADERS
#  define USTR_CONF_II_PROTO static USTR__INLINE
# else
#  define USTR_CONF_II_PROTO extern inline
# endif
#endif

#ifndef USTR_CONF_e_PROTO /* internal, unless INCLUDE_CODEONLY_HEADERS=1 */
#define USTR_CONF_e_PROTO static USTR__INLINE
#endif
#ifndef USTR_CONF_i_PROTO /* implementation of "external", dito. */
#define USTR_CONF_i_PROTO static USTR__INLINE
#endif

/* GCC helper macros */
#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_FMT && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_FMT(x, y) \
 __attribute__ ((__format__ (__printf__, x, y)))
#else
# define USTR__COMPILE_ATTR_FMT(x, y) /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_NONNULL && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_NONNULL_A() \
 __attribute__ ((__nonnull__))
# define USTR__COMPILE_ATTR_NONNULL_L(x) \
 __attribute__ ((__nonnull__ x))
#else
# define USTR__COMPILE_ATTR_NONNULL_A() /* nothing */
# define USTR__COMPILE_ATTR_NONNULL_L(x) /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_PURE && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_PURE() \
 __attribute__ ((__pure__))
#else
# define USTR__COMPILE_ATTR_PURE() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_CONST && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_CONST() \
 __attribute__ ((__const__))
#else
# define USTR__COMPILE_ATTR_CONST() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_MALLOC && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_MALLOC() \
 __attribute__ ((__malloc__))
#else
# define USTR__COMPILE_ATTR_MALLOC() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_WARN_UNUSED_RET && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_WARN_UNUSED_RET() \
 __attribute__ ((__warn_unused_result__))
#else
# define USTR__COMPILE_ATTR_WARN_UNUSED_RET() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_UNUSED && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_UNUSED(x) ustr__UNUSED_ ## x __attribute__((unused))
#else
# define USTR__COMPILE_ATTR_UNUSED(x) ustr__UNUSED_ ## x
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_DEPRECATED && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_DEPRECATED() __attribute__ ((__deprecated__))
#else
# define USTR__COMPILE_ATTR_DEPRECATED() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    USTR_CONF_HAVE_ATTR_SENTINEL && USTR_CONF_COMPILE_USE_ATTRIBUTES
# define USTR__COMPILE_ATTR_SENTINEL(x) \
 __attribute__ ((__sentinel__ (x)))
#else
# define USTR__COMPILE_ATTR_SENTINEL(x) /* nothing */
#endif

