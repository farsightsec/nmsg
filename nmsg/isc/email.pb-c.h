#ifndef PROTOBUF_C_email_2eproto__INCLUDED
#define PROTOBUF_C_email_2eproto__INCLUDED

#include <nmsg/protobuf-c.h>

PROTOBUF_C_BEGIN_DECLS


typedef struct _Nmsg__Isc__Email Nmsg__Isc__Email;


/* --- enums --- */

typedef enum _Nmsg__Isc__EmailType {
  NMSG__ISC__EMAIL_TYPE__unknown = 0,
  NMSG__ISC__EMAIL_TYPE__spamtrap = 1,
  NMSG__ISC__EMAIL_TYPE__rej_network = 2,
  NMSG__ISC__EMAIL_TYPE__rej_content = 3,
  NMSG__ISC__EMAIL_TYPE__rej_user = 4
} Nmsg__Isc__EmailType;

/* --- messages --- */

struct  _Nmsg__Isc__Email
{
  ProtobufCMessage base;
  protobuf_c_boolean has_type;
  Nmsg__Isc__EmailType type;
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
  size_t n_bodyurl;
  ProtobufCBinaryData *bodyurl;
};
#define NMSG__ISC__EMAIL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nmsg__isc__email__descriptor) \
    , 0,0, 0,0, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0,NULL, 0,NULL }


/* Nmsg__Isc__Email methods */
void   nmsg__isc__email__init
                     (Nmsg__Isc__Email         *message);
size_t nmsg__isc__email__get_packed_size
                     (const Nmsg__Isc__Email   *message);
size_t nmsg__isc__email__pack
                     (const Nmsg__Isc__Email   *message,
                      uint8_t             *out);
size_t nmsg__isc__email__pack_to_buffer
                     (const Nmsg__Isc__Email   *message,
                      ProtobufCBuffer     *buffer);
Nmsg__Isc__Email *
       nmsg__isc__email__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nmsg__isc__email__free_unpacked
                     (Nmsg__Isc__Email *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Nmsg__Isc__Email_Closure)
                 (const Nmsg__Isc__Email *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    nmsg__isc__email_type__descriptor;
extern const ProtobufCMessageDescriptor nmsg__isc__email__descriptor;

PROTOBUF_C_END_DECLS


#endif  /* PROTOBUF_email_2eproto__INCLUDED */
