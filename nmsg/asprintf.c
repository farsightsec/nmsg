/* imported from remctl-2.12 */

/* Replacement for a missing asprintf and vasprintf.
 *
 * Provides the same functionality as the standard GNU library routines
 * asprintf and vasprintf for those platforms that don't have them.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * This work is hereby placed in the public domain by its author.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "asprintf.h"

int
nmsg_asprintf(char **strp, const char *fmt, ...) {
	va_list args;
	int status;

	va_start(args, fmt);
	status = nmsg_vasprintf(strp, fmt, args);
	va_end(args);
	return (status);
}

int
nmsg_vasprintf(char **strp, const char *fmt, va_list args) {
	va_list args_copy;
	int status, needed;

	va_copy(args_copy, args);
	needed = vsnprintf(NULL, 0, fmt, args_copy);
	va_end(args_copy);
	if (needed < 0) {
		*strp = NULL;
		return (needed);
	}
	*strp = malloc(needed + 1);
	if (*strp == NULL)
		return (-1);
	status = vsnprintf(*strp, needed + 1, fmt, args);
	if (status >= 0)
		return (status);
	else {
		free(*strp);
		*strp = NULL;
		return (status);
	}
}
