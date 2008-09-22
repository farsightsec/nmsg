#include "pb_nmsg_isc.h"
size_t nmsg__isc__ncap__get_packed_size
                     (const Nmsg__Isc__Ncap *message)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__ncap__descriptor);
  return protobuf_c_message_get_packed_size ((ProtobufCMessage*)(message));
}
size_t nmsg__isc__ncap__pack
                     (const Nmsg__Isc__Ncap *message,
                      uint8_t       *out)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__ncap__descriptor);
  return protobuf_c_message_pack ((ProtobufCMessage*)message, out);
}
size_t nmsg__isc__ncap__pack_to_buffer
                     (const Nmsg__Isc__Ncap *message,
                      ProtobufCBuffer *buffer)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__ncap__descriptor);
  return protobuf_c_message_pack_to_buffer ((ProtobufCMessage*)message, buffer);
}
Nmsg__Isc__Ncap *
       nmsg__isc__ncap__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Nmsg__Isc__Ncap *)
     protobuf_c_message_unpack (&nmsg__isc__ncap__descriptor,
                                allocator, len, data);
}
void   nmsg__isc__ncap__free_unpacked
                     (Nmsg__Isc__Ncap *message,
                      ProtobufCAllocator *allocator)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__ncap__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
size_t nmsg__isc__key_value__get_packed_size
                     (const Nmsg__Isc__KeyValue *message)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__key_value__descriptor);
  return protobuf_c_message_get_packed_size ((ProtobufCMessage*)(message));
}
size_t nmsg__isc__key_value__pack
                     (const Nmsg__Isc__KeyValue *message,
                      uint8_t       *out)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__key_value__descriptor);
  return protobuf_c_message_pack ((ProtobufCMessage*)message, out);
}
size_t nmsg__isc__key_value__pack_to_buffer
                     (const Nmsg__Isc__KeyValue *message,
                      ProtobufCBuffer *buffer)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__key_value__descriptor);
  return protobuf_c_message_pack_to_buffer ((ProtobufCMessage*)message, buffer);
}
Nmsg__Isc__KeyValue *
       nmsg__isc__key_value__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Nmsg__Isc__KeyValue *)
     protobuf_c_message_unpack (&nmsg__isc__key_value__descriptor,
                                allocator, len, data);
}
void   nmsg__isc__key_value__free_unpacked
                     (Nmsg__Isc__KeyValue *message,
                      ProtobufCAllocator *allocator)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__isc__key_value__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor nmsg__isc__ncap__field_descriptors[10] =
{
  {
    "user",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_UINT32,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, n_user),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, user),
    NULL
  },
  {
    "ip4_src",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_FIXED32,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_ip4_src),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, ip4_src),
    NULL
  },
  {
    "ip4_dst",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_FIXED32,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_ip4_dst),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, ip4_dst),
    NULL
  },
  {
    "ip6_src",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_ip6_src),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, ip6_src),
    NULL
  },
  {
    "ip6_dst",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_ip6_dst),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, ip6_dst),
    NULL
  },
  {
    "i0",
    6,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_i0),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, i0),
    NULL
  },
  {
    "i1",
    7,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_i1),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, i1),
    NULL
  },
  {
    "tp",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_ENUM,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_tp),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, tp),
    &nmsg__isc__transport__descriptor
  },
  {
    "kv",
    9,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, n_kv),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, kv),
    &nmsg__isc__key_value__descriptor
  },
  {
    "payload",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, has_payload),
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__Ncap, payload),
    NULL
  },
};
static const unsigned nmsg__isc__ncap__field_indices_by_name[] = {
  5,   /* field[5] = i0 */
  6,   /* field[6] = i1 */
  2,   /* field[2] = ip4_dst */
  1,   /* field[1] = ip4_src */
  4,   /* field[4] = ip6_dst */
  3,   /* field[3] = ip6_src */
  8,   /* field[8] = kv */
  9,   /* field[9] = payload */
  7,   /* field[7] = tp */
  0,   /* field[0] = user */
};
static const ProtobufCIntRange nmsg__isc__ncap__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 10 }
};
const ProtobufCMessageDescriptor nmsg__isc__ncap__descriptor =
{
  PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC,
  "nmsg.isc.Ncap",
  "Ncap",
  "Nmsg__Isc__Ncap",
  "nmsg.isc",
  sizeof(Nmsg__Isc__Ncap),
  10,
  nmsg__isc__ncap__field_descriptors,
  nmsg__isc__ncap__field_indices_by_name,
  1,  nmsg__isc__ncap__number_ranges
};
static const ProtobufCFieldDescriptor nmsg__isc__key_value__field_descriptors[2] =
{
  {
    "key",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__KeyValue, key),
    NULL
  },
  {
    "val",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    PROTOBUF_C_OFFSETOF(Nmsg__Isc__KeyValue, val),
    NULL
  },
};
static const unsigned nmsg__isc__key_value__field_indices_by_name[] = {
  0,   /* field[0] = key */
  1,   /* field[1] = val */
};
static const ProtobufCIntRange nmsg__isc__key_value__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor nmsg__isc__key_value__descriptor =
{
  PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC,
  "nmsg.isc.KeyValue",
  "KeyValue",
  "Nmsg__Isc__KeyValue",
  "nmsg.isc",
  sizeof(Nmsg__Isc__KeyValue),
  2,
  nmsg__isc__key_value__field_descriptors,
  nmsg__isc__key_value__field_indices_by_name,
  1,  nmsg__isc__key_value__number_ranges
};
const ProtobufCEnumValue nmsg__isc__iscnmsg_types__enum_values_by_number[2] =
{
  { "MSG_NCAP", "NMSG__ISC__ISCNMSG_TYPES__MSG_NCAP", 0 },
  { "MSG_KV", "NMSG__ISC__ISCNMSG_TYPES__MSG_KV", 1 },
};
static const ProtobufCIntRange nmsg__isc__iscnmsg_types__value_ranges[] = {
{0, 0},{0, 2}
};
const ProtobufCEnumValueIndex nmsg__isc__iscnmsg_types__enum_values_by_name[2] =
{
  { "MSG_KV", 1 },
  { "MSG_NCAP", 0 },
};
const ProtobufCEnumDescriptor nmsg__isc__iscnmsg_types__descriptor =
{
  PROTOBUF_C_ENUM_DESCRIPTOR_MAGIC,
  "nmsg.isc.ISCNmsgTypes",
  "ISCNmsgTypes",
  "Nmsg__Isc__ISCNmsgTypes",
  "nmsg.isc",
  2,
  nmsg__isc__iscnmsg_types__enum_values_by_number,
  2,
  nmsg__isc__iscnmsg_types__enum_values_by_name,
  1,
  nmsg__isc__iscnmsg_types__value_ranges
};
const ProtobufCEnumValue nmsg__isc__transport__enum_values_by_number[3] =
{
  { "T_UDP", "NMSG__ISC__TRANSPORT__T_UDP", 0 },
  { "T_TCP", "NMSG__ISC__TRANSPORT__T_TCP", 1 },
  { "T_ICMP", "NMSG__ISC__TRANSPORT__T_ICMP", 2 },
};
static const ProtobufCIntRange nmsg__isc__transport__value_ranges[] = {
{0, 0},{0, 3}
};
const ProtobufCEnumValueIndex nmsg__isc__transport__enum_values_by_name[3] =
{
  { "T_ICMP", 2 },
  { "T_TCP", 1 },
  { "T_UDP", 0 },
};
const ProtobufCEnumDescriptor nmsg__isc__transport__descriptor =
{
  PROTOBUF_C_ENUM_DESCRIPTOR_MAGIC,
  "nmsg.isc.Transport",
  "Transport",
  "Nmsg__Isc__Transport",
  "nmsg.isc",
  3,
  nmsg__isc__transport__enum_values_by_number,
  3,
  nmsg__isc__transport__enum_values_by_name,
  1,
  nmsg__isc__transport__value_ranges
};
