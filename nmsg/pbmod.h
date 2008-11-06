#ifndef NMSG_PBMOD_H
#define NMSG_PBMOD_H

#include <sys/types.h>
#include <stdint.h>

#include <nmsg/nmsg.pb-c.h>

typedef void *(*nmsg_pbmod_init_fp)(size_t max, int debug);
typedef nmsg_res (*nmsg_pbmod_fini_fp)(void *);
typedef nmsg_res (*nmsg_pbmod_pbuf2pres_fp)(Nmsg__NmsgPayload *, char **,
					    const char *);
typedef nmsg_res (*nmsg_pbmod_pres2pbuf_fp)(void *, const char *, uint8_t **,
					    size_t *);
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

nmsg_res
nmsg_pbmod_pbuf2pres(nmsg_pbmod, Nmsg__NmsgPayload *, char **, const char *);

nmsg_res
nmsg_pbmod_pres2pbuf(nmsg_pbmod, void *, const char *pres, uint8_t **pbuf,
		     size_t *sz);

nmsg_res
nmsg_pbmod_free_pbuf(nmsg_pbmod, uint8_t *pbuf);

nmsg_res
nmsg_pbmod_free_pres(nmsg_pbmod, char **pres);

#endif
