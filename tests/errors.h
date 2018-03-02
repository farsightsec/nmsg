#ifndef ERRORS_H
#define ERRORS_H 1

int g_test_status = 0, l_test_status = 0;

#define check_explicit(e)	do {	\
	if ((e)) {	\
		puts("PASS: " #e);	\
	} else {	\
		puts("FAIL: " #e);	\
		l_test_status++;	\
	} } while (0);

#define check_explicit2(e, m)	do {	\
	if ((e)) {	\
		printf("PASS: %s\n", m);	\
	} else {	\
		printf("FAIL: %s\n", m);	\
		l_test_status++;	\
	} } while (0);

#define check_explicit2_display_only(e, m)	do {	\
	if ((e)) {	\
		printf("PASS: %s\n", m);	\
	} else {	\
		printf("FAIL: %s\n", m);	\
	} } while (0);

#define check(e)	do {	\
	if (!(e)) {	\
		puts("FAIL: " #e);	\
		l_test_status++;	\
	} } while (0);

#define check_noprint(e)	do {	\
	if (!(e))	\
		l_test_status++;	\
	} while (0);

#define check_return(e)	do {	\
	if (!(e)) {	\
		puts("FAIL: " #e);	\
		l_test_status++;	\
		g_test_status += l_test_status;	\
		l_test_status = 0;	\
		return 1;	\
	} } while (0);

#define check_return_silent(e)	do {	\
	if (!(e)) {	\
		l_test_status++;	\
		g_test_status += l_test_status;	\
		l_test_status = 0;	\
		return 1;	\
	} } while (0);

#define check_abort(e)	do {	\
	if (!(e)) {	\
		puts("FAIL: " #e);	\
		l_test_status++;	\
		abort();	\
	} } while (0)

#define return_if_error(e)	do {	\
	if ((e)) {	\
		puts("FAIL: " #e);	\
		g_test_status += l_test_status;	\
		l_test_status = 0;	\
		return 1;	\
	} } while (0);

#define g_check_test_status(silent)	do {	\
	if (g_test_status) {	\
		if (!silent)	\
			printf("Encountered a total of %d error(s).\n", g_test_status);	\
		g_test_status = 0;	\
                return EXIT_FAILURE;	\
	}	\
        return EXIT_SUCCESS;	\
	} while (0)

#define l_return_test_status()	do {	\
	if (!l_test_status)	\
                return 0;	\
	g_test_status += l_test_status;	\
	l_test_status = 0;	\
        return 1;	\
	} while (0)


#endif
