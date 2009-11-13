###
### libwdns
###
AC_ARG_WITH([libwdns], AC_HELP_STRING([--with-libwdns=DIR], [libwdns installation path]),
    [], [ withval="yes" ])

internal_cflags="-I$ac_abs_top_srcdir/wreck"
internal_libadd="$ac_abs_top_srcdir/wreck/wdns/msg/libwdns_msg.la"

use_internal_wdns=false
libwdns_cflags=""
libwdns_ldflags=""
libwdns_libadd=""

if test x_$withval = x_no; then
    use_internal_wdns=true

    AC_MSG_RESULT([using internal libwdns])
    AC_DEFINE([USE_INTERNAL_WDNS], [1], [Define to 1 to use internal libwdns.])
    libwdns_cflags="$internal_cflags"
    libwdns_libadd="$internal_libadd"
fi

if test x_$withval = x_yes; then
    use_internal_wdns=false

    AC_MSG_CHECKING([for libwdns headers])
    withval="/usr /usr/local"

    libwdns_libadd="-lwdns"

    libwdns_dir=""
    for dir in $withval; do
        if test -f "$dir/include/wdns.h"; then
            found_libwdns_dir="yes"
            libwdns_dir="$dir"
            if test x_$dir != x_/usr; then
                libwdns_cflags="-I$dir/include"
            fi
            break
        fi
    done

    if test x_$found_libwdns_dir = x_yes; then
        AC_MSG_RESULT([$dir/include])

        AC_MSG_CHECKING([for libwdns library])

        if test x_$libwdns_dir != x_/usr; then
            libwdns_ldflags="-L$libwdns_dir/lib"
        fi

        save_cflags="$CFLAGS"
        save_ldflags="$LDFLAGS"
        save_libs="$LIBS"
        CFLAGS="$CFLAGS $libwdns_cflags"
        LDFLAGS="$LDFLAGS $libwdns_ldflags"
        LIBS="$LIBS $libwdns_libadd"

        AC_LINK_IFELSE(
            AC_LANG_PROGRAM([[
            #include <wdns.h>
            ]],
            [[
            wdns_msg_status status = wdns_parse_message(NULL, NULL, 0);
            ]]),
            AC_MSG_RESULT([-lwdns])
            AC_DEFINE([HAVE_WDNS], [1], [Define to 1 if libwdns works.])
            ,
            AC_MSG_FAILURE([cannot find libwdns library])
            libwdns_cflags=""
            libwdns_ldflags=""
            libwdns_libadd=""
        )

        CFLAGS="$save_cflags"
        LDFLAGS="$save_ldflags"
        LIBS="$save_libs"
    else
        use_internal_wdns=true

        AC_MSG_RESULT([using internal libwdns])
        AC_DEFINE([USE_INTERNAL_WDNS], [1], [Define to 1 to use internal libwdns.])
        libwdns_cflags="$internal_cflags"
        libwdns_libadd="$internal_libadd"
    fi
fi

AC_SUBST([libwdns_cflags])
AC_SUBST([libwdns_ldflags])
AC_SUBST([libwdns_libadd])

AM_CONDITIONAL([INTERNAL_WDNS], [test "$use_internal_wdns" = "true"])
