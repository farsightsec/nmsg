AC_PREREQ(2.60)
AC_INIT([nmsg], [0.7.0-DEV], [info@sie.isc.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_MACRO_DIR([m4])
LT_INIT([disable-static pic-only])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.9 foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

_AC_SRCDIRS(.)

AC_CONFIG_FILES([Makefile
    doc/Makefile
    doc/docbook/Makefile
    doc/doxygen/Doxyfile
    doc/doxygen/Makefile
    protobuf-c/google/protobuf-c/Makefile
    ustr/Makefile
    wreck/wdns/msg/Makefile
    nmsg/Makefile
    nmsg/isc/Makefile
    nmsg/msgmod/Makefile
    src/Makefile
    examples/Makefile
])
AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_HEADER_STDC
AC_CHECK_HEADERS([sys/socket.h dnl
    sys/time.h dnl
    sys/types.h dnl
    arpa/inet.h dnl
    netinet/in.h dnl
    fcntl.h dnl
    inttypes.h dnl
    limits.h dnl
    stddef.h dnl
    stdint.h dnl
    stdlib.h dnl
    string.h dnl
    time.h dnl
    unistd.h dnl
],, AC_MSG_ERROR([required header not found]))

AC_CHECK_HEADERS([sys/endian.h endian.h])

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
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_FUNC_ALLOCA
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STAT

AC_RUN_IFELSE(
    [AC_LANG_PROGRAM(
[[
#include <sys/types.h>
]],
[[
if (sizeof(size_t) == 8)
    return (0);
else
    return (1);
]]
    )]
    ,
    AC_DEFINE([HAVE_64BIT_SIZE_T], [1], [Define to 1 if size_t is a 64 bit quantity.])
)

###
### directories
###
m4_sinclude(autoconf/ac_define_dir.m4)

AC_DEFINE_DIR([NMSG_ETCDIR], ["sysconfdir"], [nmsg etc directory])

AC_ARG_WITH(
    [plugindir],
    AC_HELP_STRING([--with-plugindir=DIR], [libnmsg plugin directory]),
    [ AC_DEFINE_DIR([NMSG_LIBDIR], ["withval"], [nmsg lib directory]) ],
    [
        if test x_$prefix = x_NONE; then
            nmsg_libdir=$ac_default_prefix/lib/nmsg
        else
            nmsg_libdir=$prefix/lib/nmsg
        fi
        AC_DEFINE_DIR([NMSG_LIBDIR], ["nmsg_libdir"], [nmsg lib directory])
    ]
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
    EXTRA_CFLAGS="$EXTRA_CFLAGS -std=gnu99"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wall"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wunused"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wshadow"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wpointer-arith"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wwrite-strings"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wnested-externs"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wmissing-prototypes"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wbad-function-cast"
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Wformat-nonliteral"
    MYAC_PROG_CC_CFLAGS_OPT([-Wextra])
    MYAC_PROG_CC_CFLAGS_OPT([-Wswitch-enum])
    MYAC_PROG_CC_CFLAGS_OPT([-fgnu89-inline])
fi

AC_SUBST([EXTRA_CFLAGS])

###
### pthreads
###
m4_sinclude(autoconf/acx_pthread.m4)
ACX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
])

###
### net
###
m4_sinclude(autoconf/check_net.m4)
m4_sinclude(autoconf/check_endianness.m4)

###
### libprotobuf-c
###
m4_sinclude(autoconf/check_libprotobuf-c.m4)

###
### libpcap
###
m4_sinclude(autoconf/check_libpcap.m4)

save_ldflags="$LDFLAGS"
save_libs="$LIBS"
CFLAGS="$CFLAGS $libpcap_cflags"
LDFLAGS="$LDFLAGS $libpcap_ldpath"

AC_SEARCH_LIBS([pcap_create], [pcap],
    AC_DEFINE([HAVE_PCAP_CREATE], [1], [Define to 1 if pcap_create() is available.])
)

LDFLAGS="$save_ldflags"
LIBS="$save_libs"

###
### libustr
###
m4_sinclude(autoconf/check_libustr.m4)

###
###
### libwdns
m4_sinclude(autoconf/check_libwdns.m4)

###
### zlib
###
m4_sinclude(autoconf/check_libz.m4)

###
### zmq
###
m4_sinclude(autoconf/check_libzmq.m4)

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

        plugin directory:       ${NMSG_LIBDIR}

        internal libprotobuf-c: ${use_internal_libprotobuf_c}
        internal libustr:       ${use_internal_libustr}
        internal libwdns:       ${use_internal_libwdns}
])
