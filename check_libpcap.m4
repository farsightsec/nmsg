###
### libpcap
###
AC_ARG_WITH([libpcap], AC_HELP_STRING([--with-libpcap=DIR], [libpcap installation path]),
    [], [ withval="yes" ])
AC_MSG_CHECKING([for libpcap headers])
if test x_$withval = x_yes; then
    withval="/usr /usr/local"
fi

libpcap_cflags=""
libpcap_ldflags=""
libpcap_libs="-lpcap"

libpcap_dir=""
for dir in $withval; do
    if test -f "$dir/include/pcap.h"; then
        found_libpcap_dir="yes"
        libpcap_dir="$dir"
        if test x_$dir != x_/usr; then
            libpcap_cflags="-I$dir/include"
        fi
        break;
    fi
done

if test x_$found_libpcap_dir = x_yes; then
    AC_MSG_RESULT([$dir])
else
    AC_MSG_ERROR([cannot find libpcap.h in $withval])
fi

AC_MSG_CHECKING([for libpcap library])

if test x_$libpcap_dir != x_/usr; then
    libpcap_ldflags="-L$libpcap_dir/lib"
fi

save_cflags="$CFLAGS"
save_ldflags="$LDFLAGS"
save_libs="$LIBS"
CFLAGS="$CFLAGS $libpcap_cflags"
LDFLAGS="$LDFLAGS $libpcap_ldflags"
LIBS="$LIBS $libpcap_libs"

AC_LINK_IFELSE(
    AC_LANG_PROGRAM([[
#include <pcap.h>
]],
[[
pcap_open_offline(0, 0);
]]),
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_LIBPCAP], [1], [Define to 1 if libpcap works.])
    ,
    AC_MSG_FAILURE([cannot find libpcap library])
    libpcap_cflags=""
    libpcap_ldflags=""
    libpcap_libs=""
)

CFLAGS="$save_cflags"
LDFLAGS="$save_ldflags"
LIBS="$save_libs"

AC_SUBST([libpcap_cflags])
AC_SUBST([libpcap_ldflags])
AC_SUBST([libpcap_libs])
