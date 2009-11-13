###
### libprotobuf-c
###
AC_ARG_WITH([libprotobuf-c], AC_HELP_STRING([--with-libprotobuf-c=DIR], [libprotobuf-c installation path]),
    [], [ withval="yes" ])

internal_cflags="-I$ac_abs_top_srcdir/protobuf-c"
internal_libadd="$ac_abs_top_srcdir/protobuf-c/google/protobuf-c/libprotobuf-c.la"

use_internal_protobuf_c=false
libprotobuf_c_cflags=""
libprotobuf_c_ldflags=""
libprotobuf_c_libadd=""

if test x_$withval = x_no; then
    use_internal_protobuf_c=true

    AC_MSG_RESULT([using internal libprotobuf-c])
    AC_DEFINE([USE_INTERNAL_PROTOBUF_C], [1], [Define to 1 to use internal libprotobuf-c.])
    libprotobuf_c_cflags="$internal_cflags"
    libprotobuf_c_libadd="$internal_libadd"
fi

if test x_$withval = x_yes; then
    use_internal_protobuf_c=false

    AC_MSG_CHECKING([for libprotobuf-c headers])
    withval="/usr /usr/local"

    libprotobuf_c_libadd="-lprotobuf-c"

    libprotobuf_c_dir=""
    for dir in $withval; do
        if test -f "$dir/include/google/protobuf-c/protobuf-c.h"; then
            found_libprotobuf_c_dir="yes"
            libprotobuf_c_dir="$dir"
            if test x_$dir != x_/usr; then
                libprotobuf_c_cflags="-I$dir/include"
            fi
            break
        fi
    done

    if test x_$found_libprotobuf_c_dir = x_yes; then
        AC_MSG_RESULT([$dir/include/google/protobuf-c])

        AC_MSG_CHECKING([for libprotobuf-c library])

        if test x_$libprotobuf_c_dir != x_/usr; then
            libprotobuf_c_ldflags="-L$libprotobuf_c_dir/lib"
        fi

        save_cflags="$CFLAGS"
        save_ldflags="$LDFLAGS"
        save_libs="$LIBS"
        CFLAGS="$CFLAGS $libprotobuf_c_cflags"
        LDFLAGS="$LDFLAGS $libprotobuf_c_ldflags"
        LIBS="$LIBS $libprotobuf_c_libadd"

        AC_LINK_IFELSE(
            AC_LANG_PROGRAM([[
            #include <google/protobuf-c/protobuf-c.h>
            ]],
            [[
            ProtobufCMessage *m = protobuf_c_message_unpack(NULL, NULL, 0, NULL);
            ]]),
            AC_MSG_RESULT([-lprotobuf-c])
            AC_DEFINE([HAVE_LIBPROTOBUF_C], [1], [Define to 1 if libprotobuf-c works.])
            ,
            AC_MSG_FAILURE([cannot find libprotobuf-c library])
            libprotobuf_c_cflags=""
            libprotobuf_c_ldflags=""
            libprotobuf_c_libadd=""
        )

        CFLAGS="$save_cflags"
        LDFLAGS="$save_ldflags"
        LIBS="$save_libs"
    else
        use_internal_protobuf_c=true

        AC_MSG_RESULT([using internal libprotobuf-c])
        AC_DEFINE([USE_INTERNAL_PROTOBUF_C], [1], [Define to 1 to use internal libprotobuf-c.])
        libprotobuf_c_cflags="$internal_cflags"
        libprotobuf_c_libadd="$internal_libadd"
    fi
fi

AC_SUBST([libprotobuf_c_cflags])
AC_SUBST([libprotobuf_c_ldflags])
AC_SUBST([libprotobuf_c_libadd])

AM_CONDITIONAL([INTERNAL_PROTOBUF_C], [test "$use_internal_protobuf_c" = "true"])
