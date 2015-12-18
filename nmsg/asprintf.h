#ifndef NMSG_ASPRINTF_H

/*! \file nmsg/asprintf.h
 * \brief Asprintf utility functions.
 *
 * Portable replacements for the asprintf(3) and vasprintf(3) functions.
 */

int nmsg_asprintf(char **strp, const char *fmt, ...);
int nmsg_vasprintf(char **strp, const char *fmt, va_list args);

#endif /* NMSG_ASPRINTF_H */
