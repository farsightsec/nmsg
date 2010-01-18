###
### libustr
###
AC_ARG_WITH([libustr], AC_HELP_STRING([--with-libustr=DIR], [libustr installation path]),
    [], [ withval="yes" ])

internal_cflags="-I$ac_abs_top_srcdir/ustr"
internal_libadd="$ac_abs_top_srcdir/ustr/libustr.la"

use_internal_libustr=false
libustr_cflags=""
libustr_ldflags=""
libustr_libadd=""

if test x_$withval = x_no; then
    use_internal_libustr=true

    AC_MSG_RESULT([using internal libustr])
    AC_DEFINE([USE_INTERNAL_LIBUSTR], [1], [Define to 1 to use internal libustr.])
    libustr_cflags="$internal_cflags"
    libustr_libadd="$internal_libadd"
fi

if test x_$withval = x_yes; then
    use_internal_libustr=false

    AC_MSG_CHECKING([for libustr headers])
    withval="/usr /usr/local"

    libustr_libadd="-lustr"

    libustr_dir=""
    for dir in $withval; do
        if test -f "$dir/include/ustr.h"; then
            found_libustr_dir="yes"
            libustr_dir="$dir"
            if test x_$dir != x_/usr; then
                libustr_cflags="-I$dir/include"
            fi
            break
        fi
    done

    if test x_$found_libustr_dir = x_yes; then
        AC_MSG_RESULT([$dir/include])

        AC_MSG_CHECKING([for libustr library])

        if test x_$libustr_dir != x_/usr; then
            libustr_ldflags="-L$libustr_dir/lib"
        fi

        save_cflags="$CFLAGS"
        save_ldflags="$LDFLAGS"
        save_libs="$LIBS"
        CFLAGS="$CFLAGS $libustr_cflags"
        LDFLAGS="$LDFLAGS $libustr_ldflags"
        LIBS="$LIBS $libustr_libadd"

        AC_LINK_IFELSE(
            AC_LANG_PROGRAM([[
            #include <ustr.h>
            ]],
            [[
            struct Ustr *s = ustr_dup_empty();
            ]]),
            AC_MSG_RESULT([-lustr])
            AC_DEFINE([HAVE_LIBUSTR], [1], [Define to 1 if libustr works.])
            ,
            AC_MSG_FAILURE([cannot find libustr library])
            libustr_cflags=""
            libustr_ldflags=""
            libustr_libadd=""
        )

        CFLAGS="$save_cflags"
        LDFLAGS="$save_ldflags"
        LIBS="$save_libs"
    else
        use_internal_libustr=true

        AC_MSG_RESULT([using internal libustr])
        AC_DEFINE([USE_INTERNAL_LIBUSTR], [1], [Define to 1 to use internal libustr.])
        libustr_cflags="$internal_cflags"
        libustr_libadd="$internal_libadd"
    fi
fi

AC_SUBST([libustr_cflags])
AC_SUBST([libustr_ldflags])
AC_SUBST([libustr_libadd])

AM_CONDITIONAL([INTERNAL_LIBUSTR], [test "$use_internal_libustr" = "true"])
