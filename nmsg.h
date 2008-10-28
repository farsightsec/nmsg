#ifndef NMSG_H
#define NMSG_H

#define nmsg_magic	{'N', 'M', 'S', 'G'}
#define nmsg_version	1U
#define nmsg_hdrsize	6

#include <nmsg/nmsg.pb-c.h>
#include <nmsg/vendors.h>

#include <stdbool.h>
#include <stdint.h>

#define nmsg_wbufsize_min	512
#define nmsg_wbufsize_max	65536
#define nmsg_wbufsize_jumbo	8192
#define nmsg_wbufsize_ether	1400
#define nmsg_rbufsize		(2 * nmsg_wbufsize_max)

#define NMSG_PBMOD_VERSION	1
#define NMSG_IDNAME_END		{ 0, NULL }

typedef enum {
	nmsg_res_failure,
	nmsg_res_success,
	nmsg_res_eof,
	nmsg_res_memfail,
	nmsg_res_magic_mismatch,
	nmsg_res_version_mismatch,
	nmsg_res_module_mismatch,
	nmsg_res_msgsize_toolarge,
	nmsg_res_short_send,
	nmsg_res_wrong_buftype,
	nmsg_res_pbuf_ready,
	nmsg_res_notimpl,
	nmsg_res_unknown_pbmod,
	nmsg_res_no_payload
} nmsg_res;

struct nmsg_idname {
	unsigned	id;
	const char	*name;
};

typedef struct nmsg_buf *nmsg_buf;
typedef struct nmsg_fma *nmsg_fma;
typedef struct nmsg_io *nmsg_io;
typedef struct nmsg_pbmod *nmsg_pbmod;
typedef struct nmsg_pbmodset *nmsg_pbmodset;
typedef struct nmsg_rate *nmsg_rate;

/* nmsg_input */
typedef void (*nmsg_cb_payload)(Nmsg__NmsgPayload *np, void *user);
extern nmsg_buf		nmsg_input_open(int fd);
extern nmsg_res		nmsg_input_close(nmsg_buf *);
extern nmsg_res		nmsg_input_loop(nmsg_buf, int cnt, nmsg_cb_payload,
					void *user);
extern nmsg_res		nmsg_input_next(nmsg_buf, Nmsg__Nmsg **);

/* nmsg_output */
extern nmsg_buf		nmsg_output_open_file(int fd, size_t bufsz);
extern nmsg_buf		nmsg_output_open_sock(int fd, size_t bufsz);
extern nmsg_res		nmsg_output_append(nmsg_buf, Nmsg__NmsgPayload *);
extern nmsg_res		nmsg_output_close(nmsg_buf *);
extern void		nmsg_output_set_allocator(nmsg_buf,
						  ProtobufCAllocator *);

/* nmsg_io */
typedef enum {
	nmsg_io_fd_type_input,
	nmsg_io_fd_type_input_pres,
	nmsg_io_fd_type_output,
	nmsg_io_fd_type_output_pres
} nmsg_io_fd_type;
typedef enum {
	nmsg_io_output_mode_stripe,
	nmsg_io_output_mode_mirror
} nmsg_io_output_mode;
typedef void (*nmsg_io_closed_fp)(nmsg_io, nmsg_io_fd_type, void *);
extern nmsg_io		nmsg_io_init(nmsg_pbmodset);
extern nmsg_res		nmsg_io_add_buf(nmsg_io, nmsg_buf, void *);
extern nmsg_res		nmsg_io_add_pres_input(nmsg_io, nmsg_pbmod, int fd, void *);
extern nmsg_res		nmsg_io_add_pres_output(nmsg_io, nmsg_pbmod, int fd, void *);
extern nmsg_res		nmsg_io_loop(nmsg_io);
extern void		nmsg_io_breakloop(nmsg_io);
extern void		nmsg_io_destroy(nmsg_io *);
extern void		nmsg_io_set_closed_fp(nmsg_io, nmsg_io_closed_fp);
extern void		nmsg_io_set_count(nmsg_io, size_t);
extern void		nmsg_io_set_debug(nmsg_io, int);
extern void		nmsg_io_set_interval(nmsg_io, size_t);
extern void		nmsg_io_set_output_mode(nmsg_io, nmsg_io_output_mode);

/* nmsg_payload */
extern Nmsg__NmsgPayload *  nmsg_payload_dup(const Nmsg__NmsgPayload *,
					     ProtobufCAllocator *);

/* nmsg_fma */
extern nmsg_fma		nmsg_fma_init(const char *, size_t, unsigned);
extern void		nmsg_fma_destroy(nmsg_fma *);
extern void *		nmsg_fma_alloc(nmsg_fma, size_t);
extern void		nmsg_fma_free(nmsg_fma, void *);

/* nmsg_pbmod */
typedef nmsg_res (*nmsg_pbmod_init_fp)(int debug);
typedef nmsg_res (*nmsg_pbmod_fini_fp)(void);
typedef nmsg_res (*nmsg_pbmod_pbuf2pres_fp)(Nmsg__NmsgPayload *, char **,
					    const char *);
typedef nmsg_res (*nmsg_pbmod_pres2pbuf_fp)(const char *, uint8_t **, size_t *);
typedef nmsg_res (*nmsg_pbmod_free_pbuf_fp)(uint8_t *);
typedef nmsg_res (*nmsg_pbmod_free_pres_fp)(char **);
struct nmsg_pbmod {
	int			pbmver;
	nmsg_pbmod_init_fp	init;
	nmsg_pbmod_fini_fp	fini;
	nmsg_pbmod_pbuf2pres_fp	pbuf2pres;
	nmsg_pbmod_pres2pbuf_fp	pres2pbuf;
	nmsg_pbmod_free_pbuf_fp	free_pbuf;
	nmsg_pbmod_free_pres_fp	free_pres;
	struct nmsg_idname	vendor;
	struct nmsg_idname	msgtype[];
};
extern nmsg_res		nmsg_pbmod_pbuf2pres(nmsg_pbmod, Nmsg__NmsgPayload *,
					     char **, const char *);
extern nmsg_res		nmsg_pbmod_pres2pbuf(nmsg_pbmod, const char *pres,
					     uint8_t **pbuf, size_t *sz);
extern nmsg_res		nmsg_pbmod_free_pbuf(nmsg_pbmod, uint8_t *pbuf);
extern nmsg_res		nmsg_pbmod_free_pres(nmsg_pbmod, char **pres);

/* nmsg_pbmodset */
extern nmsg_pbmodset	nmsg_pbmodset_open(const char *path, int debug);
extern void		nmsg_pbmodset_destroy(nmsg_pbmodset *);
extern nmsg_pbmod	nmsg_pbmodset_lookup(nmsg_pbmodset, unsigned vid,
					     unsigned msgtype);
extern unsigned		nmsg_pbmodset_mname2msgtype(nmsg_pbmodset, unsigned vid,
						    const char *mname);
extern const char *	nmsg_pbmodset_msgtype2mname(nmsg_pbmodset ms,
						    unsigned vid,
						    unsigned msgtype);
extern const char *	nmsg_pbmodset_vid2vname(nmsg_pbmodset ms, unsigned vid);
extern unsigned		nmsg_pbmodset_vname2vid(nmsg_pbmodset, const char *);

/* nmsg_rate */
extern nmsg_rate	nmsg_rate_init(int call_rate);
extern void		nmsg_rate_destroy(nmsg_rate *);
extern void		nmsg_rate_sleep(nmsg_rate);

#endif
