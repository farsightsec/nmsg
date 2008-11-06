#ifndef NMSG_OUTPUT_H
#define NMSG_OUTPUT_H

#include <sys/types.h>

#include <nmsg.h>
#include <nmsg/nmsg.pb-c.h>

nmsg_buf
nmsg_output_open_file(int fd, size_t bufsz);

nmsg_buf
nmsg_output_open_sock(int fd, size_t bufsz);

nmsg_pres
nmsg_output_open_pres(int fd);

nmsg_res
nmsg_output_append(nmsg_buf, Nmsg__NmsgPayload *);

nmsg_res
nmsg_output_close(nmsg_buf *);

void
nmsg_output_set_allocator(nmsg_buf, ProtobufCAllocator *);

void
nmsg_output_set_rate(nmsg_buf, unsigned, unsigned);

#endif
