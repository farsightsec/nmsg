#ifndef NMSG_H
#define NMSG_H

#define nmsg_magic	{'N', 'M', 'S', 'G'}
#define nmsg_version	1U
#define nmsg_hdrsize	6

#include <nmsg/pb_nmsg.h>
#include <nmsg/pb_nmsg_isc.h>

typedef enum {
	nmsg_res_failure,
	nmsg_res_success,
	nmsg_res_eof,
	nmsg_res_magic_mismatch,
	nmsg_res_version_mismatch,
	nmsg_res_msgsize_toolarge,
	nmsg_res_short_send,
	nmsg_res_wrong_buftype
} nmsg_res;

typedef enum {
	nmsg_buf_type_read,
	nmsg_buf_type_write
} nmsg_buf_type;

typedef struct nmsg_buf *nmsg_buf;
typedef void (*nmsg_handler)(const Nmsg__NmsgPayload *np, void *user);

/* nmsg_read */
extern nmsg_buf		nmsg_input_open_fd(int fd);
extern nmsg_buf		nmsg_input_open_file(const char *fname);
extern nmsg_res		nmsg_loop(nmsg_buf buf, int cnt, nmsg_handler cb, void *user);
extern nmsg_res		nmsg_read_pbuf(nmsg_buf buf, Nmsg__Nmsg **nmsg);

/* nmsg_write */
extern nmsg_buf		nmsg_output_open_fd(int fd);
extern nmsg_buf		nmsg_output_open_file(const char *fname);
extern nmsg_res		nmsg_output_append(nmsg_buf buf, Nmsg__NmsgPayload *np);
extern nmsg_res		nmsg_output_close(nmsg_buf *buf);

/* nmsg_buf */
extern void		nmsg_buf_destroy(nmsg_buf *buf);

#endif
