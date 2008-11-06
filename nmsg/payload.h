#ifndef NMSG_PAYLOAD_H
#define NMSG_PAYLOAD_H

#include <nmsg/nmsg.pb-c.h>

Nmsg__NmsgPayload *nmsg_payload_dup(const Nmsg__NmsgPayload *,
				    ProtobufCAllocator *);

#endif
