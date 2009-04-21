###
### zlib
###
AC_ARG_WITH([zlib], AC_HELP_STRING([--with-zlib=DIR],
    [zlib installation path]), [], [ withval="yes" ])
AC_MSG_CHECKING([for zlib headers])
if test x_$withval = x_yes; then
    withval="/usr /usr/local"
fi

zlib_dir=""
zlib_cflags=""
for dir in $withval; do
    if test -f "$dir/include/zlib.h"; then
        found_zlib_dir="yes"
        zlib_dir="$dir"
        if test x_$dir != x_/usr; then
            zlib_cflags="-I$dir/include"
        fi
        break
    fi
done

AC_SUBST([zlib_cflags])

if test x_$found_zlib_dir = x_yes; then
    AC_MSG_RESULT([$dir])
else
    AC_MSG_ERROR([cannot find zlib.h in $withval])
fi

AC_MSG_CHECKING([for zlib library])

if test x_$zlib_dir != x_/usr; then
    zlib_ldflags="-L$zlib_dir/lib -lz"
else
    zlib_ldflags="-lz"
fi

save_cflags="$CFLAGS"
save_ldflags="$LDFLAGS"
CFLAGS="$CFLAGS $zlib_cflags"
LDFLAGS="$LDFLAGS $zlib_ldflags"

AC_LINK_IFELSE(
    AC_LANG_PROGRAM([[
#include <zlib.h>
]],
[[
inflateInit(0);
]]),
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_ZLIB], [1], [Define to 1 if zlib works.])
    ,
    AC_MSG_FAILURE([cannot find zlib library])
    zlib_ldflags=""
)

CFLAGS="$save_cflags"
LDFLAGS="$save_ldflags"
AC_SUBST([zlib_ldflags])
