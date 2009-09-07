#include "config.h"

#if DEBUG
# define VERBOSE(format, ...) do { printf(format, ## __VA_ARGS__); } while (0)
#else
# define VERBOSE(format, ...)
#endif
