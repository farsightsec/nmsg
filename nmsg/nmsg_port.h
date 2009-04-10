#ifndef NMSG_PORT_H
#define NMSG_PORT_H

#include "config.h"

#ifdef __linux__
# define _GNU_SOURCE
# include <features.h>
# define __FAVOR_BSD
#endif

#include <stddef.h>
#include <sys/types.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef alloca
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# elif defined __GNUC__
#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
void *alloca (size_t);
# endif
#endif

#undef __attribute__
#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 95)
# define __attribute__(x)	__attribute__(x)
#else
# define __attribute__(x)
#endif

#endif
