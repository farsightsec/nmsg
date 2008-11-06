#ifndef NMSG_INPUT_H
#define NMSG_INPUT_H

#include <nmsg.h>
#include <nmsg/nmsg.pb-c.h>

typedef void (*nmsg_cb_payload)(Nmsg__NmsgPayload *np, void *user);

nmsg_buf
nmsg_input_open(int fd);

nmsg_pres
nmsg_input_open_pres(int fd, unsigned vid, unsigned msgtype);

nmsg_res
nmsg_input_close(nmsg_buf *);

nmsg_res
nmsg_input_loop(nmsg_buf, int count, nmsg_cb_payload, void *user);

nmsg_res
nmsg_input_next(nmsg_buf, Nmsg__Nmsg **);

#endif
