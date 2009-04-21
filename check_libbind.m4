###
### libbind
###
AC_ARG_WITH([libbind], AC_HELP_STRING([--with-libbind=DIR],
    [libbind installation path]), [], [ withval="yes" ])
AC_MSG_CHECKING([for libbind headers])
if test x_$withval = x_yes; then
    withval="/usr /usr/local"
fi

libbind_dir=""
libbind_cflags=""
for dir in $withval; do
    if test -f "$dir/include/bind/arpa/nameser.h"; then
        found_libbind_dir="yes"
        libbind_dir="$dir"
        if test x_$dir != x_/usr; then
            libbind_cflags="-I$dir/include/bind"
        fi
        break
    fi
done

AC_SUBST([libbind_cflags])

if test x_$found_libbind_dir = x_yes; then
    AC_MSG_RESULT([$dir])
else
    AC_MSG_RESULT([not found])
fi

AC_MSG_CHECKING([for libbind library])

if test x_$libbind_dir != x_/usr; then
    libbind_ldflags="-L$libbind_dir/lib -lbind"
else
    libbind_ldflags="-lbind"
fi

save_cflags="$CFLAGS"
save_ldflags="$LDFLAGS"
CFLAGS="$CFLAGS $libbind_cflags"
LDFLAGS="$LDFLAGS $libbind_ldflags"

AC_LINK_IFELSE(
    AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
]],
[[
ns_initparse(0,0,0);
ns_name_uncompress(0,0,0,0,0);
]]),
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_LIBBIND], [1], [Define to 1 if libbind works.])
    ,
    AC_MSG_RESULT([not found])
    libbind_ldflags=""
)

CFLAGS="$save_cflags"
LDFLAGS="$save_ldflags"
AC_SUBST([libbind_ldflags])
