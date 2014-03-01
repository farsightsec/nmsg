AC_PREREQ(2.60)
AC_INIT([nmsg], [0.8.0-rc2])
AC_CONFIG_SRCDIR([nmsg/nmsg.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

AC_PROG_LN_S

AC_CONFIG_FILES([Makefile doc/doxygen/Doxyfile nmsg/libnmsg.pc])
AC_CONFIG_HEADER([config.h])

PKG_PROG_PKG_CONFIG
if test -n "$PKG_CONFIG"; then
    # Horrible hack for systems where the pkg-config install directory is simply wrong!
    if $PKG_CONFIG --variable=pc_path pkg-config 2>/dev/null | grep -q /libdata/; then
        PKG_INSTALLDIR(['${prefix}/libdata/pkgconfig'])
    else
        PKG_INSTALLDIR
    fi
else
    AC_MSG_ERROR([pkg-config is required!])
fi

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CHECK_HEADERS([libgen.h])

AC_SEARCH_LIBS([socket], [socket])
AC_CHECK_FUNCS([socket])

AC_SEARCH_LIBS([inet_pton], [nsl])
AC_CHECK_FUNCS([inet_pton])

AC_SEARCH_LIBS([clock_gettime], [rt])
AC_CHECK_FUNCS([clock_gettime])

AC_SEARCH_LIBS([clock_nanosleep], [rt])
AC_CHECK_FUNCS([clock_nanosleep])

AC_SEARCH_LIBS([dlopen], [dl])
AC_CHECK_FUNCS([dlopen])

AC_SEARCH_LIBS([floor], [m])
AC_CHECK_FUNCS([floor])

AX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
])

AC_C_BIGENDIAN

AC_CHECK_HEADERS([sys/endian.h endian.h])
AC_CHECK_DECLS([htole32, le32toh], [], [], [
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else
# ifdef HAVE_SYS_ENDIAN_H
#  include <sys/endian.h>
# endif
#endif
])

AC_CHECK_HEADERS([sys/types.h sys/socket.h])
AC_CHECK_MEMBER(
    [struct sockaddr.sa_len],
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
### External library dependencies: libpcap, libprotobuf-c, libwdns, libxs,
### libz, jansson, yaml-0.1, msgpack, libxml2
###

MY_CHECK_LIBPCAP

MY_CHECK_LIBPROTOBUF_C

PKG_CHECK_MODULES([libwdns], [libwdns])

AC_ARG_WITH([libxs], AS_HELP_STRING([--without-libxs], [Disable libxs support]))
if test "x$with_libxs" != "xno"; then
    PKG_CHECK_MODULES([libxs], [libxs >= 1.2.0])
    AC_DEFINE([HAVE_LIBXS], [1], [Define to 1 if libxs support is enabled.])
    use_libxs="true"
else
    use_libxs="false"
fi

AC_ARG_WITH([jansson], AS_HELP_STRING([--without-jansson], [Disable jansson support]))
if test "x$with_jansson" != "xno"; then
    PKG_CHECK_MODULES([jansson], [jansson >= 2.3])
    AC_DEFINE([HAVE_JANSSON], [1], [Define to 1 if jansson support is enabled.])
    use_jansson="true"
else
    use_jansson="false"
fi

AC_ARG_WITH([yaml], AS_HELP_STRING([--without-yaml], [Disable yaml support]))
if test "x$with_yaml" != "xno"; then
    PKG_CHECK_MODULES([yaml], [yaml-0.1 >= 0.1.4])
    AC_DEFINE([HAVE_YAML], [1], [Define to 1 if yaml support is enabled.])
    use_yaml="true"
else
    use_yaml="false"
fi

AC_ARG_WITH([msgpack], AS_HELP_STRING([--without-msgpack], [Disable msgpack support]))
if test "x$with_msgpack" != "xno"; then
    dnl PKG_CHECK_MODULES([msgpack], [msgpack >= 0.5])
    AC_CHECK_HEADERS([msgpack.h])
    AC_DEFINE([HAVE_MSGPACK], [1], [Define to 1 if msgpack support is enabled.])
    AC_SUBST([msgpack_CFLAGS], [])
    AC_SUBST([msgpack_LIBS], [-lmsgpack])
    use_msgpack="true"
else
    use_msgpack="false"
fi

AC_ARG_WITH([libxml2], AS_HELP_STRING([--without-libxml2], [Disable libxml2 support]))
if test "x$with_libxml2" != "xno"; then
    PKG_CHECK_MODULES([libxml2], [libxml-2.0 >= 2.8])
    AC_DEFINE([HAVE_LIBXML2], [1], [Define to 1 if libxml2 support is enabled.])
    dnl check for LIBXML_TREE_ENABLED LIBXML_OUTPUT_ENABLED
    use_libxml2="true"
else
    use_libxml2="false"
fi

AC_CHECK_HEADER([zlib.h], [], [ AC_MSG_ERROR([required header file not found]) ])
AC_CHECK_LIB([z], [deflate], [], [ AC_MSG_ERROR([required library not found]) ])

###
### External documentation toolchain dependencies: doxygen, docbook
###

AC_PATH_PROG([DOXYGEN], [doxygen])
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
if test -n "$DOXYGEN"; then
    DOC_HTML_MSG="yes, doxygen available: $DOXYGEN"
else
    DOC_HTML_MSG="no, doxygen not available"
fi

AX_PROG_XSLTPROC([--nonet])
MY_CHECK_DOCBOOK_NS_XSLT_MIN(1.76.1)
AM_CONDITIONAL([BUILD_MAN], [test "x$XSLTPROC" != "x" -a "x$DOCBOOK_NS_XSLT_CURRENT_VERSION" != "xno"])
if test "x$XSLTPROC" != "x" -a "x$DOCBOOK_NS_XSLT_CURRENT_VERSION" != "xno"; then
    DOC_MAN_MSG="yes"
else
    DOC_MAN_MSG="no"
fi

###
### libnmsg etc and plugin directories.
###

AX_DEFINE_DIR([NMSG_ETCDIR], ["sysconfdir"], [nmsg etc directory])

AC_ARG_WITH(
    [plugindir],
    AC_HELP_STRING([--with-plugindir=DIR], [libnmsg plugin directory]),
    [ AX_DEFINE_DIR([NMSG_LIBDIR], ["withval"], [nmsg lib directory]) ],
    [
        if test x_$prefix = x_NONE; then
            nmsg_libdir=$ac_default_prefix/lib/nmsg
        else
            nmsg_libdir=$prefix/lib/nmsg
        fi
        AX_DEFINE_DIR([NMSG_LIBDIR], ["nmsg_libdir"], [nmsg lib directory])
    ]
)

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
        pkgconfigdir:           ${pkgconfigdir}

        plugin directory:       ${NMSG_LIBDIR}

        bigendian:              ${ac_cv_c_bigendian}
        libxs support:          ${use_libxs}
        jansson support:        ${use_jansson}
        yaml support:           ${use_yaml}
        msgpack support:        ${use_msgpack}
	libxml2 support:        ${use_libxml2}

        building html docs:     ${DOC_HTML_MSG}
        building manpage docs:  ${DOC_MAN_MSG}
])
