#ifndef PROTOBUF_C_ipconn_2eproto__INCLUDED
#define PROTOBUF_C_ipconn_2eproto__INCLUDED

#include <nmsg/protobuf-c.h>

PROTOBUF_C_BEGIN_DECLS


typedef struct _Nmsg__Isc__IPConn Nmsg__Isc__IPConn;


/* --- enums --- */


/* --- messages --- */

struct  _Nmsg__Isc__IPConn
{
  ProtobufCMessage base;
  protobuf_c_boolean has_proto;
  uint32_t proto;
  protobuf_c_boolean has_srcip;
  ProtobufCBinaryData srcip;
  protobuf_c_boolean has_srcport;
  uint32_t srcport;
  protobuf_c_boolean has_dstip;
  ProtobufCBinaryData dstip;
  protobuf_c_boolean has_dstport;
  uint32_t dstport;
};
#define NMSG__ISC__IPCONN__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nmsg__isc__ipconn__descriptor) \
    , 0,0, 0,{0,NULL}, 0,0, 0,{0,NULL}, 0,0 }


/* Nmsg__Isc__IPConn methods */
void   nmsg__isc__ipconn__init
                     (Nmsg__Isc__IPConn         *message);
size_t nmsg__isc__ipconn__get_packed_size
                     (const Nmsg__Isc__IPConn   *message);
size_t nmsg__isc__ipconn__pack
                     (const Nmsg__Isc__IPConn   *message,
                      uint8_t             *out);
size_t nmsg__isc__ipconn__pack_to_buffer
                     (const Nmsg__Isc__IPConn   *message,
                      ProtobufCBuffer     *buffer);
Nmsg__Isc__IPConn *
       nmsg__isc__ipconn__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nmsg__isc__ipconn__free_unpacked
                     (Nmsg__Isc__IPConn *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Nmsg__Isc__IPConn_Closure)
                 (const Nmsg__Isc__IPConn *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor nmsg__isc__ipconn__descriptor;

PROTOBUF_C_END_DECLS


#endif  /* PROTOBUF_ipconn_2eproto__INCLUDED */
