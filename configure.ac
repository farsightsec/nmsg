AC_INIT([nmsg], [0.0.0pre], [info@sie.isc.org])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.9 foreign])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_FUNC_ALLOCA
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h stddef.h stdint.h stdlib.h string.h unistd.h])

AC_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([atoi atol exit fclose fgets fopen fprintf fputc free fwrite getenv malloc memmove memset read realloc sprintf snprintf sscanf strchr strcmp strcpy strlen strncmp strncpy strsep],, AC_MSG_ERROR([required function not found]))

AC_SEARCH_LIBS([dlopen], [dl])

AC_DEFINE_UNQUOTED([NMSG_LIBDIR], ["$prefix/lib/nmsg"], [lib directory])

###
### C compiler checks
###
AC_C_INLINE
AC_C_CONST

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
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wall -Werror -Wunused -Wshadow"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wpointer-arith -Wwrite-strings -Wnested-externs"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wmissing-prototypes -Wbad-function-cast"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wformat-nonliteral"
    MYAC_PROG_CC_CFLAGS_OPT([-Wextra])
    MYAC_PROG_CC_CFLAGS_OPT([-Wswitch-enum])
    case $host in
        *-*-darwin*)
            EXTRA_CFLAGS="$EXTRA_CFLAGS -Wno-unused"
        ;;
    esac
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

AC_OUTPUT
