/*
 * Copyright (c) 2016 by Farsight Security, Inc.
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

/* Import. */

#include <sys/time.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <nmsg/fltmod_plugin.h>

#include "libmy/my_alloc.h"

/* Macros. */

#define _nmsg_dprintf(level, format, ...) \
do { \
	if (nmsg_get_debug() >= (level)) \
		fprintf(stderr, format, ##__VA_ARGS__); \
} while (0)

/* Private declarations. */

typedef enum {
	/**
	 * Systematic count-based sampling.
	 * Every k-th message is selected.
	 */
	sample_type_count,

	/**
	 * Uniform probabilistic sampling.
	 * The same selection probability is applied to all messages.
	 */
	sample_type_random,
} sample_type;

struct sample_options {
	sample_type		type;
	union {
		/**
		 * sample_type_count: select every k-th message.
		 */
		uintmax_t	k;

		/**
		 * sample_type_random: message selection probability.
		 */
		double		p;
	};
};

struct sample_thread_state {
	/**
	 * 48-bit PRNG state for per-thread erand48() / nrand48().
	 */
	unsigned short		xsubi[3];

	union {
		/**
		 * sample_type_count: per-thread message counter.
		 */
		uintmax_t	count;
	};
};

/* Functions. */

static nmsg_res
sample_module_init(const void *param,
		   const size_t len_param,
		   void **mod_data)
{
	char *my_param = NULL;
	struct sample_options *sopt = NULL;

	/**
	 * Validate module parameter.
	 *
	 * 'param' should be a \0 terminated C string containing 'len_param'
	 * bytes of data, including the terminating \0.
	 */
	if (param == NULL) {
		_nmsg_dprintf(1, "%s: module parameter is required but missing\n", __func__);
		goto err;
	}
	if (len_param != strlen(param) + 1) {
		_nmsg_dprintf(1, "%s: module parameter length mismatch\n", __func__);
		goto err;
	}

	/* Make a copy of the caller's const parameter, for strtok_r() to clobber. */
	my_param = my_strdup(param);

	/**
	 * Parse module parameter.
	 *
	 * The module parameter must be something like "count=<INTEGER>" or
	 * "random=<DOUBLE>", where <INTEGER> is a number that can be parsed by
	 * strtoumax() and <DOUBLE> is a number that can be parsed by strtod().
	 * Then we apply range restrictions to those numbers.
	 *
	 * Specifying the "count=..." parameter selects systematic count-based
	 * sampling (sample_type_count), while specifying the "random=..."
	 * parameter selects uniform probabilistic sampling
	 * (sample_type_random).
	 *
	 * If we add optional fields to the module parameter, we'll split them
	 * on "," characters.
	 */
	char *saveptr = NULL;
	char *tok1 = strtok_r(my_param, "=,", &saveptr);
	char *tok2 = strtok_r(NULL, "=,", &saveptr);
	char *tok3 = strtok_r(NULL, "=,", &saveptr);

	if (tok1 == NULL ||
	    tok2 == NULL ||
	    tok3 != NULL)
	{
		/* Parse error. */
		_nmsg_dprintf(1, "%s: error parsing module parameter '%s'\n",
			      __func__, (char *) param);
		goto err;
	}
	
	/* Allocate space for module-wide options. */
	sopt = my_calloc(1, sizeof(*sopt));

	/* Parse module option "count" or "random". */
	if (strcasecmp(tok1, "count") == 0) {
		sopt->type = sample_type_count;

		/* Attempt numeric conversion. */
		char *t = NULL;
		uintmax_t val = strtoumax(tok2, &t, 0);
		if (*t != '\0') {
			/* Parse error. */
			_nmsg_dprintf(1, "%s: error converting string to integer: '%s'\n",
				      __func__, tok2);
			goto err;
		}
		if (val < 1) {
			/* Parameter out of range. */
			_nmsg_dprintf(1, "%s: 'count' value %" PRIuMAX
				      " is out of range [1, %" PRIuMAX "]\n",
				      __func__, val, UINTMAX_MAX);
			goto err;
		}
		/* Store module-wide option "k". */
		sopt->k = val;
	} else if (strcasecmp(tok1, "random") == 0) {
		sopt->type = sample_type_random;

		/* Attempt numeric conversion. */
		char *t = NULL;
		double val = strtod(tok2, &t);
		if (*t != '\0') {
			/* Parse error. */
			_nmsg_dprintf(1, "%s: error converting string to floating point value: '%s'\n",
				      __func__, tok2);
			goto err;
		}
		if (val < 0.0 || val > 1.0) {
			/* Parameter out of range. */
			_nmsg_dprintf(1, "%s: 'random' value %s is out of range [0.0, 1.0]\n",
				      __func__, tok2);
			goto err;
		}
		/* Store module-wide option "p". */
		sopt->p = val;
	} else {
		/* Parse error, unrecognized option. */
		_nmsg_dprintf(1, "%s: unrecognized option '%s'\n", __func__, tok1);
		goto err;
	}

	my_free(my_param);
	*mod_data = sopt;
	return nmsg_res_success;
err:
	my_free(sopt);
	my_free(my_param);
	return nmsg_res_failure;
}

static void
sample_module_fini(void *mod_data)
{
	my_free(mod_data);
}

static nmsg_res
sample_thread_init(void *mod_data, void **thr_data)
{
	if (!mod_data) {
		return nmsg_res_failure;
	}

	struct sample_options *sopt = (struct sample_options *) mod_data;
	struct sample_thread_state *state = my_calloc(1, sizeof(*state));

	/* Initialize state->xsubi, seed for this thread's random generator. */
	struct timeval tv = {0};
	gettimeofday(&tv, NULL);
	uint32_t seed = (unsigned) tv.tv_sec + (unsigned) tv.tv_usec + (unsigned) pthread_self();
	memcpy(state->xsubi, &seed, sizeof(seed));

	switch (sopt->type) {
	case sample_type_count:
		/**
		 * Initialize state->count to a random value modulo k so that
		 * threads don't "clump" their selections.
		 */
		state->count = nrand48(state->xsubi) % sopt->k;
		break;
	case sample_type_random:
		break;
	}

	*thr_data = state;
	return nmsg_res_success;
}

static nmsg_res
sample_thread_fini(void *mod_data, void *thr_data)
{
	my_free(thr_data);
	return nmsg_res_success;
}

static nmsg_res
sample_filter_message(nmsg_message_t *msg,
		      void *mod_data,
		      void *thr_data,
		      nmsg_filter_message_verdict *vres)
{
	if (!mod_data || !thr_data) {
		return nmsg_res_failure;
	}

	struct sample_options *sopt = (struct sample_options *) mod_data;
	struct sample_thread_state *state = (struct sample_thread_state *) thr_data;

	*vres = nmsg_filter_message_verdict_DECLINED;

	switch (sopt->type) {
	case sample_type_count:
		state->count += 1;
		if (state->count >= sopt->k) {
			/* Selected the k-th message. */
			state->count = 0;
			*vres = nmsg_filter_message_verdict_DECLINED;
		} else {
			/* Dropped message. */
			*vres = nmsg_filter_message_verdict_DROP;
		}
		break;
	case sample_type_random:
		if (erand48(state->xsubi) < sopt->p) {
			/* Message was selected with probability p. */
			*vres = nmsg_filter_message_verdict_DECLINED;
		} else {
			/* Dropped message. */
			*vres = nmsg_filter_message_verdict_DROP;
		}
		break;
	}

	return nmsg_res_success;
}

/* Export. */

struct nmsg_fltmod_plugin nmsg_fltmod_plugin_export = {
	NMSG_FLTMOD_REQUIRED_INIT,

	.module_init		= sample_module_init,
	.module_fini		= sample_module_fini,
	.thread_init		= sample_thread_init,
	.thread_fini		= sample_thread_fini,
	.filter_message		= sample_filter_message,
};
