#include "pb_nmsg.h"
size_t nmsg__nmsg__get_packed_size
                     (const Nmsg__Nmsg *message)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg__descriptor);
  return protobuf_c_message_get_packed_size ((ProtobufCMessage*)(message));
}
size_t nmsg__nmsg__pack
                     (const Nmsg__Nmsg *message,
                      uint8_t       *out)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg__descriptor);
  return protobuf_c_message_pack ((ProtobufCMessage*)message, out);
}
size_t nmsg__nmsg__pack_to_buffer
                     (const Nmsg__Nmsg *message,
                      ProtobufCBuffer *buffer)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg__descriptor);
  return protobuf_c_message_pack_to_buffer ((ProtobufCMessage*)message, buffer);
}
Nmsg__Nmsg *
       nmsg__nmsg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Nmsg__Nmsg *)
     protobuf_c_message_unpack (&nmsg__nmsg__descriptor,
                                allocator, len, data);
}
void   nmsg__nmsg__free_unpacked
                     (Nmsg__Nmsg *message,
                      ProtobufCAllocator *allocator)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
size_t nmsg__nmsg_payload__get_packed_size
                     (const Nmsg__NmsgPayload *message)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg_payload__descriptor);
  return protobuf_c_message_get_packed_size ((ProtobufCMessage*)(message));
}
size_t nmsg__nmsg_payload__pack
                     (const Nmsg__NmsgPayload *message,
                      uint8_t       *out)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg_payload__descriptor);
  return protobuf_c_message_pack ((ProtobufCMessage*)message, out);
}
size_t nmsg__nmsg_payload__pack_to_buffer
                     (const Nmsg__NmsgPayload *message,
                      ProtobufCBuffer *buffer)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg_payload__descriptor);
  return protobuf_c_message_pack_to_buffer ((ProtobufCMessage*)message, buffer);
}
Nmsg__NmsgPayload *
       nmsg__nmsg_payload__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Nmsg__NmsgPayload *)
     protobuf_c_message_unpack (&nmsg__nmsg_payload__descriptor,
                                allocator, len, data);
}
void   nmsg__nmsg_payload__free_unpacked
                     (Nmsg__NmsgPayload *message,
                      ProtobufCAllocator *allocator)
{
  PROTOBUF_C_ASSERT (message->base.descriptor == &nmsg__nmsg_payload__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor nmsg__nmsg__field_descriptors[1] =
{
  {
    "payloads",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    PROTOBUF_C_OFFSETOF(Nmsg__Nmsg, n_payloads),
    PROTOBUF_C_OFFSETOF(Nmsg__Nmsg, payloads),
    &nmsg__nmsg_payload__descriptor
  },
};
static const unsigned nmsg__nmsg__field_indices_by_name[] = {
  0,   /* field[0] = payloads */
};
static const ProtobufCIntRange nmsg__nmsg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor nmsg__nmsg__descriptor =
{
  PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC,
  "nmsg.Nmsg",
  "Nmsg",
  "Nmsg__Nmsg",
  "nmsg",
  sizeof(Nmsg__Nmsg),
  1,
  nmsg__nmsg__field_descriptors,
  nmsg__nmsg__field_indices_by_name,
  1,  nmsg__nmsg__number_ranges
};
static const ProtobufCFieldDescriptor nmsg__nmsg_payload__field_descriptors[5] =
{
  {
    "vid",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_ENUM,
    0,   /* quantifier_offset */
    PROTOBUF_C_OFFSETOF(Nmsg__NmsgPayload, vid),
    &nmsg__vendor__descriptor
  },
  {
    "msgtype",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    PROTOBUF_C_OFFSETOF(Nmsg__NmsgPayload, msgtype),
    NULL
  },
  {
    "time_sec",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    PROTOBUF_C_OFFSETOF(Nmsg__NmsgPayload, time_sec),
    NULL
  },
  {
    "time_nsec",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_FIXED32,
    0,   /* quantifier_offset */
    PROTOBUF_C_OFFSETOF(Nmsg__NmsgPayload, time_nsec),
    NULL
  },
  {
    "payload",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    PROTOBUF_C_OFFSETOF(Nmsg__NmsgPayload, has_payload),
    PROTOBUF_C_OFFSETOF(Nmsg__NmsgPayload, payload),
    NULL
  },
};
static const unsigned nmsg__nmsg_payload__field_indices_by_name[] = {
  1,   /* field[1] = msgtype */
  4,   /* field[4] = payload */
  3,   /* field[3] = time_nsec */
  2,   /* field[2] = time_sec */
  0,   /* field[0] = vid */
};
static const ProtobufCIntRange nmsg__nmsg_payload__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor nmsg__nmsg_payload__descriptor =
{
  PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC,
  "nmsg.NmsgPayload",
  "NmsgPayload",
  "Nmsg__NmsgPayload",
  "nmsg",
  sizeof(Nmsg__NmsgPayload),
  5,
  nmsg__nmsg_payload__field_descriptors,
  nmsg__nmsg_payload__field_indices_by_name,
  1,  nmsg__nmsg_payload__number_ranges
};
const ProtobufCEnumValue nmsg__vendor__enum_values_by_number[1] =
{
  { "V_ISC", "NMSG__VENDOR__V_ISC", 1 },
};
static const ProtobufCIntRange nmsg__vendor__value_ranges[] = {
{1, 0},{0, 1}
};
const ProtobufCEnumValueIndex nmsg__vendor__enum_values_by_name[1] =
{
  { "V_ISC", 0 },
};
const ProtobufCEnumDescriptor nmsg__vendor__descriptor =
{
  PROTOBUF_C_ENUM_DESCRIPTOR_MAGIC,
  "nmsg.Vendor",
  "Vendor",
  "Nmsg__Vendor",
  "nmsg",
  1,
  nmsg__vendor__enum_values_by_number,
  1,
  nmsg__vendor__enum_values_by_name,
  1,
  nmsg__vendor__value_ranges
};
