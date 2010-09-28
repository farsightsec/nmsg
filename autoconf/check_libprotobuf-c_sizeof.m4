if test "$use_internal_libprotobuf_c" != "true"; then
    AC_CHECK_SIZEOF(ProtobufCMessageDescriptor,, [[#include <google/protobuf-c/protobuf-c.h>]])
    AC_CHECK_SIZEOF(ProtobufCFieldDescriptor,,   [[#include <google/protobuf-c/protobuf-c.h>]])
    AC_CHECK_SIZEOF(ProtobufCEnumDescriptor,,    [[#include <google/protobuf-c/protobuf-c.h>]])

    if test "$ac_cv_sizeof_ProtobufCEnumDescriptor" != "120"; then
        AC_MSG_FAILURE([sizeof(ProtobufCEnumDescriptor) != 120])
    fi

    if test "$ac_cv_sizeof_ProtobufCFieldDescriptor" != "72"; then
        AC_MSG_FAILURE([sizeof(ProtobufCFieldDescriptor) != 72])
    fi

    if test "$ac_cv_sizeof_ProtobufCMessageDescriptor" != "120"; then
        AC_MSG_FAILURE([sizeof(ProtobufCMessageDescriptor) != 120])
    fi
fi
