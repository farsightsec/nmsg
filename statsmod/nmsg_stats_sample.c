#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <nmsg/statsmod_plugin.h>

#include "../libmy/my_alloc.h"
#include "../libmy/vector.h"


/* Macros. */

#define _nmsg_dprintf(level, format, ...) \
do { \
	if (nmsg_get_debug() >= (level)) \
		fprintf(stderr, format, ##__VA_ARGS__); \
} while (0)


/* Private declarations. */

struct metrics_list {
	uint64_t total_payloads_in;
	uint64_t total_payloads_out;
	uint64_t total_container_recvs;
	uint64_t total_container_lost;

	/* Lifetime rolling averages: */
	uint64_t payloads_in_per_sec;
	uint64_t payloads_out_per_sec;
	uint64_t container_recvs_per_sec;
};

struct stats_io {
	nmsg_io_t io;
	const char *name;
	struct metrics_list metrics;
};

VECTOR_GENERATE(io_vec, struct stats_io)

struct stats_data {
	FILE   *outfile;
	io_vec *ios;
	time_t update_delta_secs;
	pthread_t update_thread;
	bool stop;

	struct metrics_list metrics;
};


/* Functions. */

static nmsg_res
update_stats(struct stats_data *sdata)
{
	nmsg_res res = nmsg_res_success;
	static __thread uint64_t num_updates = 0;

	uint64_t total_payloads_in     = 0;
	uint64_t total_payloads_out    = 0;
	uint64_t total_container_recvs = 0;
	uint64_t total_container_lost  = 0;

	num_updates++;

	for (size_t i = 0; i < io_vec_size(sdata->ios); i++) {
		struct stats_io *current_io = &io_vec_data(sdata->ios)[i];

		uint64_t payloads_in     = 0;
		uint64_t payloads_out    = 0;
		uint64_t container_recvs = 0;
		uint64_t container_lost  = 0;

		if (nmsg_io_get_stats(current_io->io, &payloads_in, &payloads_out,
				      &container_recvs, &container_lost) != nmsg_res_success) {
			res = nmsg_res_failure;
			continue;
		}

		current_io->metrics.total_payloads_in = payloads_in;
		current_io->metrics.total_payloads_out = payloads_out;
		current_io->metrics.total_container_recvs = container_recvs;
		current_io->metrics.total_container_lost = container_lost;

		current_io->metrics.payloads_in_per_sec = (payloads_in / num_updates)
			/ sdata->update_delta_secs;
		current_io->metrics.payloads_out_per_sec = (payloads_out / num_updates)
			/ sdata->update_delta_secs;
		current_io->metrics.container_recvs_per_sec = (container_recvs / num_updates)
			/ sdata->update_delta_secs;

		total_payloads_in     += payloads_in;
		total_payloads_out    += payloads_out;
		total_container_recvs += container_recvs;
		total_container_lost  += container_lost;

	}

	sdata->metrics.total_payloads_in     = total_payloads_in;
	sdata->metrics.total_payloads_out    = total_payloads_out;
	sdata->metrics.total_container_recvs = total_container_recvs;
	sdata->metrics.total_container_lost  = total_container_lost;

	sdata->metrics.payloads_in_per_sec = (total_payloads_in / num_updates) /
		sdata->update_delta_secs;
	sdata->metrics.payloads_out_per_sec = (total_payloads_out / num_updates) /
		sdata->update_delta_secs;
	sdata->metrics.container_recvs_per_sec = (total_container_recvs / num_updates) /
		sdata->update_delta_secs;

	return res;
}

static void
print_metrics(FILE *outfile, struct metrics_list metrics)
{
	fprintf(outfile, "Total payloads in:\t%zu\n", metrics.total_payloads_in);
	fprintf(outfile, "Total payloads out:\t%zu\n", metrics.total_payloads_out);
	fprintf(outfile, "Total container recvs:\t%zu\n", metrics.total_container_recvs);
	fprintf(outfile, "Total containers lost:\t%zu\n", metrics.total_container_lost);
	fprintf(outfile, "Avg payloads in per second:\t%zu\n", metrics.payloads_in_per_sec);
	fprintf(outfile, "Avg payloads out per second:\t%zu\n", metrics.payloads_out_per_sec);
	fprintf(outfile, "Avg container recvs per second:\t%zu\n", metrics.container_recvs_per_sec);
}

static void *
update_stats_thread(void *arg)
{
	struct stats_data *sdata = arg;

	while (!sdata->stop) {
		time_t time_utc;
		struct tm *time_local;
		char *time_local_str;

		sleep(sdata->update_delta_secs);

		time(&time_utc);
		time_local = localtime(&time_utc);
		time_local_str = asctime(time_local);

		fprintf(sdata->outfile, "========================================\n");
		fprintf(sdata->outfile, "timestamp:\t%s", time_local_str);

		if (update_stats(sdata) != nmsg_res_success) {
			fprintf(sdata->outfile, "ERROR: Could not update metrics!\n");
			continue;
		}

		print_metrics(sdata->outfile, sdata->metrics);
		for (size_t i = 0; i < io_vec_size(sdata->ios); i++) {
			struct stats_io current_io;
			current_io = io_vec_value(sdata->ios, i);
			fprintf(sdata->outfile, "===Metrics for IO: %s===\n", current_io.name);
			print_metrics(sdata->outfile, current_io.metrics);
		}

		fflush(sdata->outfile);
	}

	return 0;
}

static nmsg_res
parse_args(struct stats_data *sdata, char *param_list)
{
	char *param_tok;

	while ((param_tok = strtok_r(param_list, ",", &param_list))) {
		char *opt_value = param_tok;
		char *opt_name = strtok_r(opt_value, "=", &opt_value);

		if (strcmp(opt_name, "out") == 0) {
			sdata->outfile = fopen(opt_value, "w");
			if (sdata->outfile == NULL) {
				_nmsg_dprintf(1, "%s: file \"%s\" could not be "
					"opened for writing\n", __func__, opt_value);
				return nmsg_res_failure;
			}

		} else if (strcmp(opt_name, "secs") == 0) {
			sdata->update_delta_secs = strtoul(opt_value, NULL, 10);
			if (sdata->update_delta_secs == 0) {
				_nmsg_dprintf(1, "%s: invalid update frequency "
					"value \"%s\" (must be a number greater "
					"than 0)\n", __func__, opt_value);
				return nmsg_res_failure;
			}

		} else /* The parameter name is unrecognized. */ {
			_nmsg_dprintf(1, "%s: invalid module parameter \"%s\"\n",
				__func__, opt_name);
			return nmsg_res_failure;
		}
	}

	return nmsg_res_success;
}

/* Init function required for nmsg statsmod plugins. */
static nmsg_res
sample_module_init(const void *param,
                   const size_t len_param,
                   void **mod_data)
{
	struct stats_data *sdata = calloc(1, sizeof(*sdata));
	sdata->outfile = stderr;
	sdata->update_delta_secs = 1;

	/*
	 * Parse the parameters supplied by the caller.
	 *
	 * Parameter format is defined by the module and caller.  For this module,
	 * we parse the parameters as comma-separated key-value pairs.
	 */
	if (param != NULL) {
		char *param_dup;
		nmsg_res parse_res;

		param_dup = strndup(param, len_param);
		parse_res = parse_args(sdata, (char *) param_dup);
		my_free(param_dup);

		if (parse_res != nmsg_res_success) {
			my_free(sdata);
			return nmsg_res_failure;
		}
	}

	sdata->ios = io_vec_init(1);
	pthread_create(&sdata->update_thread, NULL, &update_stats_thread, sdata);
	*mod_data = sdata;
	return nmsg_res_success;
}

/* Finish/cleanup function required for nmsg statsmod plugins. */
static void
sample_module_fini(void *mod_data)
{
	struct stats_data *sdata = mod_data;
	if (sdata == NULL)
		return;

	sdata->stop = true;
	pthread_join(sdata->update_thread, NULL);
	io_vec_destroy(&sdata->ios);

	if (sdata->outfile != stderr && sdata->outfile != stdout && sdata->outfile != NULL)
		fclose(sdata->outfile);

	my_free(sdata);
}

/* Function that executes on nmsg IO add, required for nmsg statsmod plugins. */
static nmsg_res
sample_module_io_add(void *mod_data, nmsg_io_t io, const char *name)
{
	struct stats_data *sdata = mod_data;
	struct stats_io new_io = {0};

	if (sdata == NULL)
		return nmsg_res_failure;

	new_io.io = io;
	new_io.name = name;
	io_vec_add(sdata->ios, new_io);

	return nmsg_res_success;
}

/* Function that executes on nmsg IO remove, required for nmsg statsmod plugins. */
static nmsg_res
sample_module_io_remove(void *mod_data, nmsg_io_t io)
{
	size_t io_count;
	struct stats_data *sdata = mod_data;
	if (sdata == NULL)
		return nmsg_res_failure;

	io_count = io_vec_size(sdata->ios);
	for (size_t i = 0; i < io_count; i++) {
		if (io == io_vec_value(sdata->ios, i).io) {
			if (i + 1 < io_count) {
				struct stats_io last = io_vec_value(sdata->ios, io_count - 1);
				io_vec_data(sdata->ios)[i] = last;
			}
			io_vec_clip(sdata->ios, io_count - 1);
		}
	}

	return nmsg_res_success;
}


/* Export. */

/* Expose functions to the caller.  This struct is required for statsmod plugins. */
struct nmsg_statsmod_plugin nmsg_statsmod_plugin_export = {
	NMSG_STATSMOD_REQUIRED_INIT,

	.module_init = sample_module_init,
	.module_fini = sample_module_fini,
	.io_add      = sample_module_io_add,
	.io_remove   = sample_module_io_remove,
};
