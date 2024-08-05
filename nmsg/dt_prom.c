/*
 * Copyright (c) 2024 DomainTools LLC
 *
 *  Prometheus+microhttpd embedding routines.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dt_prom.h"

#include <pthread.h>

#include <microhttpd.h>


static prom_callback g_prom_cb;
static struct MHD_Daemon *mhd_daemon = NULL;


#if MHD_VERSION >= 0x00097002
static enum MHD_Result
#else
static int
#endif
promhttp_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
	const char *version __attribute__((unused)), const char *upload_data __attribute__((unused)),
	size_t *upload_data_size __attribute__((unused)), void **con_cls __attribute__((unused)))
{
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	const char *buf;
	struct MHD_Response *response;
	enum MHD_ResponseMemoryMode mmode = MHD_RESPMEM_PERSISTENT;
	unsigned int status_code = MHD_HTTP_BAD_REQUEST;
	int ret;

	pthread_mutex_lock(&lock);

	if (g_prom_cb(cls) < 0) {
		buf = "Statistics retrieval failure\n";
		status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
		goto resp;
	}

	if (strcmp(method, "GET") != 0)
		buf = "Invalid HTTP Method\n";
	else if (strcmp(url, "/") == 0) {
		buf = "OK\n";
		status_code = MHD_HTTP_OK;
	} else if (strcmp(url, "/metrics") == 0) {
		buf = prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
		mmode = MHD_RESPMEM_MUST_FREE;
		status_code = MHD_HTTP_OK;
	} else
		buf = "Bad Request\n";

resp:
	response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, mmode);
	ret = MHD_queue_response(connection, status_code, response);
	MHD_destroy_response(response);
	pthread_mutex_unlock(&lock);

	return ret;
}

static int
init_microhttpd(void *clos, unsigned short port)
{
#if MHD_VERSION >= 0x00095300
	const int flags = MHD_USE_INTERNAL_POLLING_THREAD;
#else
	const int flags = MHD_USE_POLL_INTERNALLY;
#endif

	mhd_daemon = MHD_start_daemon(flags, port, NULL, NULL, &promhttp_handler, clos, MHD_OPTION_END);
	return (mhd_daemon != NULL ? 0 : -1);
}

int
init_prometheus(prom_callback cbfn, void *clos, unsigned short port)
{
	static unsigned int once = 0;

	if (once++ > 0)
		return -1;

	if (prom_collector_registry_default_init() != 0)
		return -1;

	g_prom_cb = cbfn;

	return (init_microhttpd(clos, port));
}

void
stop_prometheus(void)
{
	if (mhd_daemon != NULL)
		MHD_stop_daemon(mhd_daemon);
}
