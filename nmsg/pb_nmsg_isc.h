#ifndef PROTOBUF_C_nmsg_5fisc_2eproto__INCLUDED
#define PROTOBUF_C_nmsg_5fisc_2eproto__INCLUDED

#include <nmsg/protobuf-c.h>

PROTOBUF_C_BEGIN_DECLS


typedef struct _Nmsg__Isc__Ncap Nmsg__Isc__Ncap;
typedef struct _Nmsg__Isc__KeyValue Nmsg__Isc__KeyValue;


/* --- enums --- */

typedef enum _Nmsg__Isc__ISCNmsgTypes {
  NMSG__ISC__ISCNMSG_TYPES__MSG_NCAP = 0,
  NMSG__ISC__ISCNMSG_TYPES__MSG_KV = 1
} Nmsg__Isc__ISCNmsgTypes;
typedef enum _Nmsg__Isc__Network {
  NMSG__ISC__NETWORK__IP4 = 0,
  NMSG__ISC__NETWORK__IP6 = 1
} Nmsg__Isc__Network;
typedef enum _Nmsg__Isc__Transport {
  NMSG__ISC__TRANSPORT__UDP = 0,
  NMSG__ISC__TRANSPORT__TCP = 1,
  NMSG__ISC__TRANSPORT__ICMP = 2
} Nmsg__Isc__Transport;

/* --- messages --- */

struct  _Nmsg__Isc__Ncap
{
  ProtobufCMessage base;
  size_t n_user;
  uint32_t *user;
  Nmsg__Isc__Network np;
  Nmsg__Isc__Transport tp;
  ProtobufCBinaryData np_src;
  ProtobufCBinaryData np_dst;
  int32_t tp_i0;
  int32_t tp_i1;
  size_t n_kv;
  Nmsg__Isc__KeyValue **kv;
  protobuf_c_boolean has_payload;
  ProtobufCBinaryData payload;
};
#define NMSG__ISC__NCAP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nmsg__isc__ncap__descriptor) \
    , 0,NULL, 0, 0, {0,NULL}, {0,NULL}, 0, 0, 0,NULL, 0,{0,NULL} }


struct  _Nmsg__Isc__KeyValue
{
  ProtobufCMessage base;
  ProtobufCBinaryData key;
  ProtobufCBinaryData val;
};
#define NMSG__ISC__KEY_VALUE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nmsg__isc__key_value__descriptor) \
    , {0,NULL}, {0,NULL} }


/* Nmsg__Isc__Ncap methods */
size_t nmsg__isc__ncap__get_packed_size
                     (const Nmsg__Isc__Ncap   *message);
size_t nmsg__isc__ncap__pack
                     (const Nmsg__Isc__Ncap   *message,
                      uint8_t             *out);
size_t nmsg__isc__ncap__pack_to_buffer
                     (const Nmsg__Isc__Ncap   *message,
                      ProtobufCBuffer     *buffer);
Nmsg__Isc__Ncap *
       nmsg__isc__ncap__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nmsg__isc__ncap__free_unpacked
                     (Nmsg__Isc__Ncap *message,
                      ProtobufCAllocator *allocator);
/* Nmsg__Isc__KeyValue methods */
size_t nmsg__isc__key_value__get_packed_size
                     (const Nmsg__Isc__KeyValue   *message);
size_t nmsg__isc__key_value__pack
                     (const Nmsg__Isc__KeyValue   *message,
                      uint8_t             *out);
size_t nmsg__isc__key_value__pack_to_buffer
                     (const Nmsg__Isc__KeyValue   *message,
                      ProtobufCBuffer     *buffer);
Nmsg__Isc__KeyValue *
       nmsg__isc__key_value__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nmsg__isc__key_value__free_unpacked
                     (Nmsg__Isc__KeyValue *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Nmsg__Isc__Ncap_Closure)
                 (const Nmsg__Isc__Ncap *message,
                  void *closure_data);
typedef void (*Nmsg__Isc__KeyValue_Closure)
                 (const Nmsg__Isc__KeyValue *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    nmsg__isc__iscnmsg_types__descriptor;
extern const ProtobufCEnumDescriptor    nmsg__isc__network__descriptor;
extern const ProtobufCEnumDescriptor    nmsg__isc__transport__descriptor;
extern const ProtobufCMessageDescriptor nmsg__isc__ncap__descriptor;
extern const ProtobufCMessageDescriptor nmsg__isc__key_value__descriptor;

PROTOBUF_C_END_DECLS


#endif  /* PROTOBUF_nmsg_5fisc_2eproto__INCLUDED */
