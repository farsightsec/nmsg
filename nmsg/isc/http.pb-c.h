#ifndef PROTOBUF_C_http_2eproto__INCLUDED
#define PROTOBUF_C_http_2eproto__INCLUDED

#include <nmsg/protobuf-c.h>

PROTOBUF_C_BEGIN_DECLS


typedef struct _Nmsg__Isc__Http Nmsg__Isc__Http;


/* --- enums --- */

typedef enum _Nmsg__Isc__HttpType {
  NMSG__ISC__HTTP_TYPE__unknown = 0,
  NMSG__ISC__HTTP_TYPE__sinkhole = 1
} Nmsg__Isc__HttpType;

/* --- messages --- */

struct  _Nmsg__Isc__Http
{
  ProtobufCMessage base;
  Nmsg__Isc__HttpType type;
  protobuf_c_boolean has_srcip;
  ProtobufCBinaryData srcip;
  protobuf_c_boolean has_srchost;
  ProtobufCBinaryData srchost;
  protobuf_c_boolean has_srcport;
  uint32_t srcport;
  protobuf_c_boolean has_dstip;
  ProtobufCBinaryData dstip;
  protobuf_c_boolean has_dstport;
  uint32_t dstport;
  protobuf_c_boolean has_request;
  ProtobufCBinaryData request;
  protobuf_c_boolean has_p0f;
  ProtobufCBinaryData p0f;
};
#define NMSG__ISC__HTTP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nmsg__isc__http__descriptor) \
    , 0, 0,{0,NULL}, 0,{0,NULL}, 0,0, 0,{0,NULL}, 0,0, 0,{0,NULL}, 0,{0,NULL} }


/* Nmsg__Isc__Http methods */
void   nmsg__isc__http__init
                     (Nmsg__Isc__Http         *message);
size_t nmsg__isc__http__get_packed_size
                     (const Nmsg__Isc__Http   *message);
size_t nmsg__isc__http__pack
                     (const Nmsg__Isc__Http   *message,
                      uint8_t             *out);
size_t nmsg__isc__http__pack_to_buffer
                     (const Nmsg__Isc__Http   *message,
                      ProtobufCBuffer     *buffer);
Nmsg__Isc__Http *
       nmsg__isc__http__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nmsg__isc__http__free_unpacked
                     (Nmsg__Isc__Http *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Nmsg__Isc__Http_Closure)
                 (const Nmsg__Isc__Http *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    nmsg__isc__http_type__descriptor;
extern const ProtobufCMessageDescriptor nmsg__isc__http__descriptor;

PROTOBUF_C_END_DECLS


#endif  /* PROTOBUF_http_2eproto__INCLUDED */
