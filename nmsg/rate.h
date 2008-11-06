#ifndef NMSG_RATE_H
#define NMSG_RATE_H

#include <nmsg.h>

nmsg_rate
nmsg_rate_init(unsigned rate, unsigned freq);

void
nmsg_rate_destroy(nmsg_rate *);

void
nmsg_rate_sleep(nmsg_rate);

#endif
