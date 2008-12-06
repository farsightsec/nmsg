#ifndef NMSG_ASPRINTF_H

#include <stdarg.h>

int nmsg_asprintf(char **, const char *, ...);
int nmsg_vasprintf(char **, const char *, va_list);

#endif /* NMSG_ASPRINTF_H */
