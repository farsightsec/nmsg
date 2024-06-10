AC_PREREQ(2.64)

m4_define(nmsg_major_version, 1)
m4_define(nmsg_minor_version, 1)
m4_define(nmsg_patchlevel_version, 2)
m4_define(nmsg_version,
	  nmsg_major_version.nmsg_minor_version.nmsg_patchlevel_version)
m4_define(nmsg_version_number,
	  m4_eval(nmsg_major_version * 1000000 + nmsg_minor_version * 1000 + nmsg_patchlevel_version))

AC_INIT([nmsg],
        [nmsg_version()],
        [https://github.com/farsightsec/nmsg/issues],
        [nmsg],
        [https://github.com/farsightsec/nmsg])
AC_CONFIG_SRCDIR([nmsg/nmsg.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

NMSG_MAJOR_VERSION=nmsg_major_version()
NMSG_MINOR_VERSION=nmsg_minor_version()
NMSG_PATCHLEVEL_VERSION=nmsg_patchlevel_version()
NMSG_VERSION=nmsg_version()
NMSG_VERSION_NUMBER=nmsg_version_number()

AC_SUBST(NMSG_MAJOR_VERSION)
AC_SUBST(NMSG_MINOR_VERSION)
AC_SUBST(NMSG_PATCHLEVEL_VERSION)
AC_SUBST(NMSG_VERSION)
AC_SUBST(NMSG_VERSION_NUMBER)

AC_PROG_LN_S

AC_CONFIG_FILES([Makefile doc/doxygen/Doxyfile nmsg/libnmsg.pc nmsg/version.h])

AC_CONFIG_FILES([tests/group-operator-source-tests/test.sh],
                [chmod +x tests/group-operator-source-tests/test.sh])

AC_CONFIG_FILES([tests/json-utf8-tests/test.sh],
                [chmod +x tests/json-utf8-tests/test.sh])

AC_CONFIG_FILES([tests/nmsg-dns-tests/test.sh],
                [chmod +x tests/nmsg-dns-tests/test.sh])

AC_CONFIG_FILES([tests/nmsg-dnsobs-tests/test.sh],
                [chmod +x tests/nmsg-dnsobs-tests/test.sh])

AC_CONFIG_FILES([tests/nmsg-dnsqr-tests/test.sh],
                [chmod +x tests/nmsg-dnsqr-tests/test.sh])

AC_CONFIG_FILES([tests/nmsg-dnstap-tests/test.sh],
                [chmod +x tests/nmsg-dnstap-tests/test.sh])

AC_CONFIG_FILES([tests/nmsg-http-tests/test.sh],
                [chmod +x tests/nmsg-http-tests/test.sh])

AC_CONFIG_FILES([tests/udp-checksum-tests/test.sh],
                [chmod +x tests/udp-checksum-tests/test.sh])

AC_CONFIG_FILES([tests/payload-crc32c-tests/test.sh],
                [chmod +x tests/payload-crc32c-tests/test.sh])

AC_CONFIG_FILES([tests/string-tests/test.sh],
                [chmod +x tests/string-tests/test.sh])

AC_CONFIG_HEADER([config.h])

my_PKG_CONFIG_FILES([LIBNMSG_PC], [nmsg/libnmsg.pc])

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
### External library dependencies: libpcap, libprotobuf-c, libwdns, zeromq, json-c, libz
###

MY_CHECK_LIBPCAP

PKG_CHECK_MODULES([libprotobuf_c], [libprotobuf-c >= 1.0.1])
AC_PATH_PROG([PROTOC_C], [protoc-c])
AS_IF([test -z "$PROTOC_C"],
      [AC_MSG_ERROR([The protoc-c program was not found. Please install the protobuf-c compiler!])])

PKG_CHECK_MODULES([libwdns], [libwdns >= 0.12.0])

AC_ARG_WITH([libzmq], AS_HELP_STRING([--without-libzmq], [Disable zmq support]))
if test "x$with_libzmq" != "xno"; then
    PKG_CHECK_MODULES([libzmq], [libzmq >= 4.2.0])
    AC_DEFINE([HAVE_LIBZMQ], [1], [Define to 1 if libzmq support is enabled.])
    use_libzmq="true"
else
    use_libzmq="false"
fi

AC_ARG_WITH([libzstd], AS_HELP_STRING([--without-libzstd], [Disable zstd support]))
if test "x$with_libzstd" != "xno"; then
    ### Note: prefer to have latest as of 6/2024: 1.5.6
    PKG_CHECK_MODULES([libzstd], [libzstd >= 0.8.0])
    AC_DEFINE([HAVE_LIBZSTD], [1], [Define to 1 if libzstd support is enabled.])
    use_libzstd="true"
else
    use_libzstd="false"
fi

AC_ARG_WITH([liblz4], AS_HELP_STRING([--without-liblz4], [Disable lz4 support]))
if test "x$with_liblz4" != "xno"; then
    ### Note: prefer to have latest as of 6/2024: 1.9.5
    # space in third argument so success does nothing (does not set LIBS)
    AC_CHECK_LIB(lz4, LZ4_compress_HC, [ ],
      [AC_MSG_ERROR([liblz4 >= r130 required])], [${liblz4_LIBS}])
    PKG_CHECK_MODULES([liblz4], [liblz4 >= 0])
    AC_DEFINE([HAVE_LIBLZ4], [1], [Define to 1 if liblz4 support is enabled.])
    use_liblz4="true"
else
    use_liblz4="false"
fi

AC_ARG_WITH([json-c], AS_HELP_STRING([--without-json-c], [Disable json-c support]))
if test "x$with_json_c" != "xno"; then
    PKG_CHECK_MODULES([json_c], [json-c >= 0.13.0])
    AC_DEFINE([HAVE_JSON_C], [1], [Define to 1 if json-c support is enabled.])
    use_json_c="true"
else
    use_json_c="false"
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
    [pluginsdir],
    AC_HELP_STRING([--with-pluginsdir=DIR], [nmsg plugins directory]),
    [ AX_DEFINE_DIR([NMSG_PLUGINSDIR], ["withval"], [nmsg plugins directory]) ],
    [
        nmsg_pluginsdir=$libdir/nmsg
        AX_DEFINE_DIR([NMSG_PLUGINSDIR], ["nmsg_pluginsdir"], [nmsg plugins directory])
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

        plugins directory:      ${NMSG_PLUGINSDIR}

        bigendian:              ${ac_cv_c_bigendian}
        libzmq support:         ${use_libzmq}
        libzstd support:        ${use_libzstd}
        liblz4 support:         ${use_liblz4}
        json-c support:         ${use_json_c}

        building html docs:     ${DOC_HTML_MSG}
        building manpage docs:  ${DOC_MAN_MSG}
])
