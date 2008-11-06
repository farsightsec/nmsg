#ifndef NMSG_H
#define NMSG_H

#include <nmsg/constants.h>
#include <nmsg/nmsg.pb-c.h>
#include <nmsg/res.h>
#include <nmsg/vendors.h>

typedef struct nmsg_buf *nmsg_buf;
typedef struct nmsg_fma *nmsg_fma;
typedef struct nmsg_io *nmsg_io;
typedef struct nmsg_pbmod *nmsg_pbmod;
typedef struct nmsg_pbmodset *nmsg_pbmodset;
typedef struct nmsg_pres *nmsg_pres;
typedef struct nmsg_rate *nmsg_rate;

struct nmsg_idname {
	unsigned	id;
	const char	*name;
};

#endif
