#include "config.h"

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if DEBUG
# define VERBOSE(format, ...) do { printf(format, ## __VA_ARGS__); } while (0)
#else
# define VERBOSE(format, ...)
#endif
