#ifndef NMSG_H
#define NMSG_H

#define nmsg_magic	{'N', 'M', 'S', 'G'}
#define nmsg_version	1U
#define nmsg_hdrsize	6

#include <nmsg/pb_nmsg.h>
#include <nmsg/pb_nmsg_isc.h>

typedef enum {
	nmsg_res_failure = 0,
	nmsg_res_success = 1,
	nmsg_res_magic_mismatch = 2,
	nmsg_res_version_mismatch = 3,
	nmsg_res_short_read = 4,
	nmsg_res_msgsize_toolarge = 5,
	nmsg_res_eof = 6,
} nmsg_res;

typedef struct nmsg_source *nmsg_source;
typedef void (*nmsg_handler)(const Nmsg__Nmsg *nmsg, void *user);

/* nmsg_read */
extern nmsg_res nmsg_loop(nmsg_source ns, int cnt, nmsg_handler cb, void *user);
extern nmsg_res nmsg_read_header(nmsg_source ns);
extern nmsg_res nmsg_read_pbuf(nmsg_source ns, Nmsg__Nmsg **nmsg);
extern nmsg_source nmsg_open_fd(int fd);
extern nmsg_source nmsg_open_file(const char *fname);
extern void nmsg_source_destroy(nmsg_source *ns);

#endif
