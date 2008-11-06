#ifndef NMSG_RES_H
#define NMSG_RES_H

typedef enum {
	nmsg_res_success,
	nmsg_res_failure,
	nmsg_res_eof,
	nmsg_res_memfail,
	nmsg_res_magic_mismatch,
	nmsg_res_version_mismatch,
	nmsg_res_module_mismatch,
	nmsg_res_msgsize_toolarge,
	nmsg_res_short_send,
	nmsg_res_wrong_buftype,
	nmsg_res_pbuf_ready,
	nmsg_res_pbuf_written,
	nmsg_res_notimpl,
	nmsg_res_unknown_pbmod,
	nmsg_res_no_payload,
	nmsg_res_stop
} nmsg_res;

#endif
