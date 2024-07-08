/*
 * Copyright (c) 2024 DomainTools LLC
 *
 *  Prometheus+microhttpd helper/function definitions for embedding.
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

#ifndef DT_PROM_H
#define DT_PROM_H

#include <prom.h>


#define INIT_PROM_CTR(ctr,name,desc)	\
	ctr = prom_collector_registry_must_register_metric(prom_counter_new(name, desc, 0, NULL));

/* Note: label MUST be of type char * and NOT a string literal. */
#define INIT_PROM_CTR_L(ctr,name,desc,label)	\
	ctr = prom_collector_registry_must_register_metric(prom_counter_new(name, desc, 1, &label));

#define INIT_PROM_GAUGE(gauge,name,desc)	\
	gauge = prom_collector_registry_must_register_metric(prom_gauge_new(name, desc, 0, NULL));

/* Note: label MUST be of type char * and NOT a string literal. */
#define INIT_PROM_GAUGE_L(gauge,name,desc,label)	\
	gauge = prom_collector_registry_must_register_metric(prom_gauge_new(name, desc, 1, &label));

/* This user callback returns 0 on success or -1 on failure. */
typedef int (*prom_callback)(void *clos);

/*
 * Initialize the prometheus subsystem.
 *
 * cbfn is a mandatory callback function that will be called with the user-
 * defined value in clos each time prometheus metrics are queried.
 *
 * Port denotes an HTTP listening port for exporting the prometheus metrics
 * via libmicrohttpd.
 */
int init_prometheus(prom_callback cbfn, void *clos, unsigned short port);

#endif /* DT_PROM_H */
