AC_PREREQ([2.61])
AC_INIT([wreck], [0.1.5], [info@sie.isc.org])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.10 foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

_AC_SRCDIRS(.)

AC_CONFIG_FILES([Makefile
    wdns/Makefile
    wdns/msg/Makefile
    examples/Makefile
    ustr/Makefile
])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

if test "x$GCC" = xyes; then
    EXTRA_CFLAGS="-Wall -Wextra -Werror -fgnu89-inline"
fi
AC_SUBST([EXTRA_CFLAGS])

AC_CHECK_HEADER([pcap.h])
AC_CHECK_LIB([pcap], [pcap_loop],
    [
        AC_DEFINE([HAVE_LIBPCAP], [1], [Define to 1 if libpcap works.])
        have_libpcap=true
    ],
    [
        have_libpcap=false
    ]
)
AM_CONDITIONAL([LIBPCAP], [test "$have_libpcap" = "true"])

AC_CHECK_HEADERS([alloca.h])
AC_CHECK_HEADERS([arpa/inet.h ctype.h inttypes.h stdbool.h stdint.h stdlib.h string.h],
    ,
    [AC_MSG_ERROR([required header file not found])]
)

AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [enable debugging])],
    [AC_DEFINE([DEBUG], [1], [Define to 1 to enable debugging.])]
)

###
### libustr
###
m4_sinclude(autoconf/check_libustr.m4)

AC_OUTPUT
