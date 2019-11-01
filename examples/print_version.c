#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#include <nmsg.h>

int
main(void) {

/* to do compile-time checking, do something like the following: */
#if NMSG_LIBRARY_VERSION_NUMBER > 13002
	printf("your install of libnmsg supports compile-time versioning ");
	printf("(NMSG_LIBRARY_VERSION_NUMBER == %d)\n",
			NMSG_LIBRARY_VERSION_NUMBER);
#else
	printf("your install of libnmsg predates versioning, consider an upgrade\n");
	return (EXIT_SUCCESS);
#endif

	/* to do run-time checking, do something like the following: */
	printf("libnmsg run-time version is %d\n", nmsg_get_version_number());

	/* and to emit a stringified version number, do this: */
	printf("this program was linked against libnmsg version %s\n",
			nmsg_get_version());

	return (EXIT_SUCCESS);
}
