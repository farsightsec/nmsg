#ifndef PROTOBUF_C_emailhdr_2eproto__INCLUDED
#define PROTOBUF_C_emailhdr_2eproto__INCLUDED

#include <nmsg/protobuf-c.h>

PROTOBUF_C_BEGIN_DECLS


typedef struct _Nmsg__Isc__Emailhdr Nmsg__Isc__Emailhdr;


/* --- enums --- */


/* --- messages --- */

struct  _Nmsg__Isc__Emailhdr
{
  ProtobufCMessage base;
  protobuf_c_boolean has_truncated;
  protobuf_c_boolean truncated;
  protobuf_c_boolean has_headers;
  ProtobufCBinaryData headers;
  protobuf_c_boolean has_srcip;
  ProtobufCBinaryData srcip;
  protobuf_c_boolean has_srchost;
  ProtobufCBinaryData srchost;
  protobuf_c_boolean has_helo;
  ProtobufCBinaryData helo;
  protobuf_c_boolean has_from;
  ProtobufCBinaryData from;
  size_t n_rcpt;
  ProtobufCBinaryData *rcpt;
};
#define NMSG__ISC__EMAILHDR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nmsg__isc__emailhdr__descriptor) \
    , 0,0, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0,NULL }


/* Nmsg__Isc__Emailhdr methods */
void   nmsg__isc__emailhdr__init
                     (Nmsg__Isc__Emailhdr         *message);
size_t nmsg__isc__emailhdr__get_packed_size
                     (const Nmsg__Isc__Emailhdr   *message);
size_t nmsg__isc__emailhdr__pack
                     (const Nmsg__Isc__Emailhdr   *message,
                      uint8_t             *out);
size_t nmsg__isc__emailhdr__pack_to_buffer
                     (const Nmsg__Isc__Emailhdr   *message,
                      ProtobufCBuffer     *buffer);
Nmsg__Isc__Emailhdr *
       nmsg__isc__emailhdr__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nmsg__isc__emailhdr__free_unpacked
                     (Nmsg__Isc__Emailhdr *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Nmsg__Isc__Emailhdr_Closure)
                 (const Nmsg__Isc__Emailhdr *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor nmsg__isc__emailhdr__descriptor;

PROTOBUF_C_END_DECLS


#endif  /* PROTOBUF_emailhdr_2eproto__INCLUDED */
