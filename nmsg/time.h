#ifndef NMSG_TIME_H
#define NMSG_TIME_H

#include <time.h>

#include <nmsg.h>

void
nmsg_time_get(struct timespec *);

void
nmsg_time_sleep(const struct timespec *);

#endif
