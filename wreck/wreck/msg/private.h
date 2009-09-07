#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <wreck.h>

#include "config.h"

#if DEBUG
# define VERBOSE(format, ...) do { printf("%s(%d): " format, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)
#else
# define VERBOSE(format, ...)
#endif
