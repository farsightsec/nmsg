#ifndef NMSG_H
#define NMSG_H

#define nmsg_magic	{'N', 'M', 'S', 'G'}
#define nmsg_version	1U
#define nmsg_hdrsize	6

#include <nmsg/pb_nmsg.h>
#include <nmsg/pb_nmsg_isc.h>

#define nmsg_wbufsize_min	512
#define nmsg_wbufsize_max	65536
#define nmsg_wbufsize_jumbo	8192
#define nmsg_wbufsize_ether	1400
#define nmsg_rbufsize		(2 * nmsg_wbufsize_max)

typedef enum {
	nmsg_res_failure,
	nmsg_res_success,
	nmsg_res_eof,
	nmsg_res_memfail,
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
typedef struct nmsg_fma *nmsg_fma;
typedef void (*nmsg_cb_payload)(Nmsg__NmsgPayload *np, void *user);

/* nmsg_read */
extern nmsg_buf		nmsg_input_open_fd(int fd);
extern nmsg_res		nmsg_loop(nmsg_buf buf, int cnt, nmsg_cb_payload cb, void *user);
extern nmsg_res		nmsg_read_pbuf(nmsg_buf buf, Nmsg__Nmsg **nmsg);

/* nmsg_write */
extern nmsg_buf		nmsg_output_open_fd(int fd, size_t bufsz);
extern nmsg_res		nmsg_output_append(nmsg_buf buf, Nmsg__NmsgPayload *np,
					   ProtobufCAllocator *ca);
extern nmsg_res		nmsg_output_close(nmsg_buf *buf, ProtobufCAllocator *ca);

/* nmsg_buf */
extern void		nmsg_buf_destroy(nmsg_buf *buf);

/* nmsg_fma */
nmsg_fma		nmsg_fma_init(const char *, size_t, unsigned);
void *			nmsg_fma_alloc(nmsg_fma, size_t);
void			nmsg_fma_free(nmsg_fma, void *);

#endif
