AC_CHECK_MEMBER([struct sockaddr.sa_len],
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
