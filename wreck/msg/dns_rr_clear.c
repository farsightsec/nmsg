#include "private.h"

void
wreck_dns_rr_clear(wreck_dns_rr_t *rr) {
	free(rr->name.data);
	free(rr->rdata);

	rr->name.data = NULL;
	rr->rdata = NULL;
}
