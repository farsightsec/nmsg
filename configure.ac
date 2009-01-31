AC_INIT([nmsg], [0.1.0], [info@sie.isc.org])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.9 foreign])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h dnl
    netinet/in.h dnl
    sys/socket.h dnl
    sys/time.h dnl
    sys/types.h dnl
    fcntl.h dnl
    inttypes.h dnl
    stddef.h dnl
    stdint.h dnl
    stdlib.h dnl
    string.h dnl
    unistd.h dnl
],, AC_MSG_ERROR([required header not found]))

AC_SEARCH_LIBS([socket], [socket])
AC_CHECK_FUNCS([socket])

AC_SEARCH_LIBS([inet_pton], [nsl])
AC_CHECK_FUNCS([inet_pton])

AC_SEARCH_LIBS([clock_gettime], [rt])
AC_CHECK_FUNCS([clock_gettime])

AC_SEARCH_LIBS([dlopen], [dl])
AC_CHECK_FUNCS([dlopen])

AC_SEARCH_LIBS([floor], [m])
AC_CHECK_FUNCS([floor])

AC_HEADER_DIRENT
AC_HEADER_STDBOOL
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_FUNC_ALLOCA
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_STRFTIME

AC_CHECK_FUNCS([atoi dnl
    atol dnl
    exit dnl
    fclose dnl
    fgets dnl
    fopen dnl
    fprintf dnl
    fputc dnl
    free dnl
    fwrite dnl
    getcwd dnl
    getenv dnl
    gettimeofday dnl
    memcmp dnl
    memmove dnl
    memset dnl
    munmap dnl
    pathconf dnl
    read dnl
    snprintf dnl
    sprintf dnl
    sscanf dnl
    strcasecmp dnl
    strncasecmp dnl
    strchr dnl
    strcmp dnl
    strcpy dnl
    strdup dnl
    strerror dnl
    strftime dnl
    strlen dnl
    strncmp dnl
    strncpy dnl
    strstr dnl
    strtok_r dnl
    strtoul dnl
    vsnprintf dnl
],, AC_MSG_ERROR([required function not found]))

if test x_$prefix = x_NONE; then
    nmsg_libdir=$ac_default_prefix/lib/nmsg
else
    nmsg_libdir=$prefix/lib/nmsg
fi
AC_DEFINE_UNQUOTED([NMSG_LIBDIR], ["$nmsg_libdir"], [lib directory])

AC_CHECK_MEMBER([struct sockaddr.sa_len],
    AC_DEFINE([HAVE_SA_LEN], [1], [Define to 1 if struct sockaddr has an sa_len member.]),
    [],
    [[
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
    ]]
)

###
### C compiler checks
###
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE

AC_DEFUN([MYAC_PROG_CC_CFLAGS_OPT],
[AC_MSG_CHECKING([if $CC supports $1])
myac_save_CFLAGS=$CFLAGS
CFLAGS="$myac_save_CFLAGS $1"
_AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
                   EXTRA_CFLAGS="$EXTRA_CFLAGS $1"
                   AC_MSG_RESULT(yes),
                   [AC_MSG_RESULT(no)])
CFLAGS="$myac_save_CFLAGS"
])

if test "x$GCC" = xyes; then
    EXTRA_CFLAGS="$EXTRA_CFLAGS -std=gnu99 -Wall -Werror -Wunused -Wshadow"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wpointer-arith -Wwrite-strings -Wnested-externs"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wmissing-prototypes -Wbad-function-cast"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wformat-nonliteral"
    MYAC_PROG_CC_CFLAGS_OPT([-Wextra])
    MYAC_PROG_CC_CFLAGS_OPT([-Wswitch-enum])
fi

AC_SUBST([EXTRA_CFLAGS])

###
### libpcap
###
AC_ARG_WITH([pcap], AC_HELP_STRING([--with-pcap], [libpcap installation path]),
    [], [ withval="yes" ])
AC_MSG_CHECKING([for pcap.h])
if test x_$withval = x_yes; then
    withval="/usr/local /opt/local /usr/pkg /usr"
fi
for dir in $withval; do
    if test -f "$dir/include/pcap.h"; then
        found_libpcap="yes"
        if test x_$dir != x_/usr; then
            CPPFLAGS="$CPPFLAGS -I$dir/include"
        fi
        break;
    fi
done
if test x_$found_libpcap = x_yes; then
    AC_MSG_RESULT([$dir/include/pcap.h])
    if test x_$dir != x_/usr; then
        LDFLAGS="$LDFLAGS -L$dir/lib"
    fi
else
    AC_MSG_ERROR([cannot find pcap.h in $withval])
fi

###
### pthreads
###
m4_sinclude(acx_pthread.m4)
ACX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
])

###
### zlib
###
m4_sinclude(check_zlib.m4)
CHECK_ZLIB()

###
### isc/list.h
###
AC_ARG_WITH([isc], AC_HELP_STRING([--with-isc], [path to ISC headers]),
    [], [ withval="yes" ])
AC_MSG_CHECKING([for isc/list.h])

if test x_$withval = x_yes; then
    withval="/usr/local /usr /opt/local /usr/pkg /usr/local/bind"
fi

save_cflags="$CFLAGS"

for dir in $withval; do
    unset ac_cv_have_decl_ISC_LIST_INIT
    CFLAGS="${save_cflags}"
    if test -f "$dir/include/isc/list.h"; then
        if test "$dir" != "/usr"; then
            CFLAGS="$CFLAGS -I$dir/include"
        fi
        AC_CHECK_DECL(ISC_LIST_INIT, found_isc="yes",, [#include <isc/list.h>])
        if test x_$found_isc = x_yes; then
            break;
        fi
    fi
done

if test x_$found_isc != x_yes; then
    AC_MSG_ERROR([cannot find working isc/list.h in $withval])
fi

AC_OUTPUT
