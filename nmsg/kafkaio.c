/*
 * Copyright (c) 2024 DomainTools LLC
 * Copyright (c) 2009-2013,2016 by Farsight Security, Inc.
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

#include "private.h"

#ifdef HAVE_LIBRDKAFKA

struct nmsg_kafka_ctx {
	bool running;
	bool stopped;
	char * topic_str;
	char * broker;
	int partition;
	bool consumer;
	int timeout;
	int64_t offset;
	rd_kafka_conf_t * config;
	rd_kafka_t *handle;
	rd_kafka_topic_t *topic;
	rd_kafka_message_t *message;
};

/* Forward. */
static bool _kafka_addr_init(nmsg_kafka_ctx_t ctx, const char *addr);

static nmsg_kafka_ctx_t _kafka_init_kafka(const char *addr, bool consumer, int timeout);

/* Private. */

static bool
_kafka_addr_init(nmsg_kafka_ctx_t ctx, const char * addr)
{
	char *pound, *at, *comma;
	ssize_t len;
	pound = strchr(addr, '#');
	at = strchr(addr, '@');
	comma = strchr(addr, ',');

	if (!pound || !at)
		return false;

	len = pound - addr;
	ctx->topic_str = my_malloc(len + 1);
	strncpy(ctx->topic_str, addr,len);
	ctx->topic_str[len] = '\0';

	sscanf(pound + 1, "%d", &ctx->partition);

	if (comma) {
		len = comma - at - 1;
		ctx->broker = my_malloc(len + 1);
		strncpy(ctx->broker, at + 1, len);
		ctx->broker[len] = '\0';

		sscanf(comma + 1, "%ld", &ctx->offset);
	} else {
		ctx->broker = my_malloc(strlen(at));
		strcpy(ctx->broker, at + 1);
		ctx->offset = RD_KAFKA_OFFSET_END;
	}

	return true;
}

static nmsg_kafka_ctx_t
_kafka_init_kafka(const char *addr, bool consumer, int timeout)
{
	struct nmsg_kafka_ctx * ctx;
	char tmp[16];
	rd_kafka_topic_conf_t *topic_conf;

	ctx = my_calloc(1, sizeof(struct nmsg_kafka_ctx));

	ctx->timeout = timeout;
	ctx->consumer = consumer;

	if (!_kafka_addr_init(ctx, addr)) {
		nmsg_kafka_ctx_destroy(ctx);
		return NULL;
	}

	ctx->config = rd_kafka_conf_new();
	if (!ctx->config) {
		nmsg_kafka_ctx_destroy(ctx);
		return NULL;
	}

	snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	if (rd_kafka_conf_set(ctx->config, "internal.termination.signal", tmp, NULL, 0) != RD_KAFKA_CONF_OK ||
		rd_kafka_conf_set(ctx->config, "bootstrap.servers", ctx->broker, NULL, 0) != RD_KAFKA_CONF_OK ||
		(consumer && rd_kafka_conf_set(ctx->config, "enable.partition.eof", "true", NULL, 0)  != RD_KAFKA_CONF_OK)) {

		nmsg_kafka_ctx_destroy(ctx);
		return NULL;
	}

	/* Create Kafka handle */
	ctx->handle = rd_kafka_new(consumer ? RD_KAFKA_CONSUMER : RD_KAFKA_PRODUCER, ctx->config, NULL, 0);
	if (!ctx->handle) {
		nmsg_kafka_ctx_destroy(ctx);
		return NULL;
	}

	/* Topic configuration */
	topic_conf = rd_kafka_topic_conf_new();
	if (!topic_conf) {
		nmsg_kafka_ctx_destroy(ctx);
		return NULL;
	}

	/* Create topic */
	ctx->topic = rd_kafka_topic_new(ctx->handle, ctx->topic_str, topic_conf);
	if (!ctx->topic) {
		nmsg_kafka_ctx_destroy(ctx);
		return NULL;
	}

	ctx->running = true;
	ctx->stopped = true;
	return ctx;
}

/* Export. */

void
nmsg_kafka_ctx_destroy(nmsg_kafka_ctx_t ctx)
{
	if (ctx->running) {
		ctx->running = false;
		if (ctx->consumer) {
			rd_kafka_consume_stop(ctx->topic, ctx->partition);	/* Stop consuming */
			while(!ctx->stopped)
				rd_kafka_poll(ctx->handle, 0);
		}
		else {
			rd_kafka_resp_err_t res = RD_KAFKA_RESP_ERR_NO_ERROR;
			while (rd_kafka_outq_len(ctx->handle) > 0 && res == RD_KAFKA_RESP_ERR_NO_ERROR)
				res = rd_kafka_flush(ctx->handle, ctx->timeout);
		}

		/* Destroy topic */
		rd_kafka_topic_destroy(ctx->topic);

		/* Destroy handle */
		rd_kafka_destroy(ctx->handle);

		my_free(ctx->topic_str);
		my_free(ctx->broker);
	}

	my_free(ctx);
}

nmsg_res
nmsg_kafka_read_start(nmsg_kafka_ctx_t ctx, uint8_t **buf, size_t *len)
{
	if (!buf || !len || !ctx || !ctx->consumer)
		return nmsg_res_failure;

	*buf = NULL;
	*len = 0;
	ctx->stopped = false;
	do {
		/* Poll for errors, etc. */
		rd_kafka_poll(ctx->handle, 0);

		ctx->message = rd_kafka_consume(ctx->topic, ctx->partition, ctx->timeout);
		if (ctx->message) {
			if (ctx->message->err != RD_KAFKA_RESP_ERR__PARTITION_EOF) {
				*buf = ctx->message->payload;
				*len = ctx->message->len;
			} else {
				rd_kafka_message_destroy(ctx->message);
				ctx->message = NULL;
			}
		}
	} while(ctx->offset == RD_KAFKA_OFFSET_END && ctx->running && !ctx->message);

	ctx->stopped = true;

	return nmsg_res_success;
}

nmsg_res
nmsg_kafka_read_close(nmsg_kafka_ctx_t ctx)
{
	if (!ctx || !ctx->consumer)
		return nmsg_res_failure;

	if (ctx->message)
		/* Return message to rdkafka */
		rd_kafka_message_destroy(ctx->message);

	return nmsg_res_success;
}

nmsg_res
nmsg_kafka_write(nmsg_kafka_ctx_t ctx, const uint8_t *buf, size_t len)
{
	int res;

	if (!ctx || ctx->consumer)
		return nmsg_res_failure;

	res = rd_kafka_produce(ctx->topic, ctx->partition, RD_KAFKA_MSG_F_FREE,
						   (void*) buf, len,		/* Payload and length */
						   NULL, 0,					/* Optional key and its length */
						   NULL);					/* Message opaque, provided in delivery report callback as message->_private. */

	/* Poll to handle delivery reports */
	rd_kafka_poll(ctx->handle, 0);

	return (res == -1) ? nmsg_res_failure : nmsg_res_success;
}

nmsg_kafka_ctx_t
nmsg_kafka_create_consumer(const char *addr, int timeout)
{
	nmsg_kafka_ctx_t ctx;

	if (!addr)
		return NULL;

	ctx = _kafka_init_kafka(addr, true, timeout);
	if (!ctx)
		return NULL;

	/* Start consuming */
	if (rd_kafka_consume_start(ctx->topic, ctx->partition, ctx->offset) == -1) {
		nmsg_kafka_ctx_destroy(ctx);
		return NULL;
	}

	return ctx;
}

nmsg_kafka_ctx_t
nmsg_kafka_create_producer(const char *addr, int timeout)
{
	if (!addr)
		return NULL;

	return _kafka_init_kafka(addr, false, timeout);
}

#if !defined(HAVE_JSON_C)
nmsg_input_t
nmsg_input_open_kafka_endpoint(const char *addr, int timeout)
{
	nmsg_kafka_ctx_t ctx;

	ctx = nmsg_kafka_create_consumer(addr, timeout);
	if (!ctx)
		return NULL;

	return nmsg_input_open_kafka(ctx);
}

nmsg_output_t
nmsg_output_open_kafka_endpoint(const char *addr, size_t bufsz, int timeout)
{
	nmsg_kafka_ctx_t ctx;

	ctx = nmsg_kafka_create_producer(addr, timeout);
	if (!ctx)
		return NULL;

	return nmsg_output_open_kafka(ctx, bufsz);
}
#endif

#else /* HAVE_LIBRDKAFKA */

/* Export. */

#include "kafkaio.h"

struct nmsg_kafka_ctx {
	bool running;
};

void
nmsg_kafka_ctx_destroy(nmsg_kafka_ctx_t ctx __attribute__((unused)))
{
}

nmsg_res
nmsg_kafka_read_start(nmsg_kafka_ctx_t ctx __attribute__((unused)),
			     uint8_t **buf __attribute__((unused)),
			     size_t *len __attribute__((unused)))
{
	return nmsg_res_failure;
}

nmsg_res
nmsg_kafka_read_close(nmsg_kafka_ctx_t ctx __attribute__((unused)))
{
	return nmsg_res_failure;
}

nmsg_res
nmsg_kafka_write(nmsg_kafka_ctx_t ctx __attribute__((unused)),
			     const uint8_t *buf __attribute__((unused)),
			     size_t len __attribute__((unused)))
{
	return nmsg_res_failure;
}

nmsg_kafka_ctx_t
nmsg_kafka_create_consumer(const char *addr __attribute__((unused)),
			     int timeout  __attribute__((unused)))
{
	return NULL;
}

nmsg_kafka_ctx_t
nmsg_kafka_create_producer(const char *addr __attribute__((unused)),
			     int timeout  __attribute__((unused)))
{
	return NULL;
}

nmsg_input_t
nmsg_input_open_kafka_endpoint(const char *ep __attribute__((unused)),
			     int timeout  __attribute__((unused)))
{
	return NULL;
}

nmsg_output_t
nmsg_output_open_kafka_endpoint(const char *addr __attribute__((unused)),
			     size_t bufsz __attribute__((unused)),
			     int timeout  __attribute__((unused)))
{
	return NULL;
}

#endif /* HAVE_LIBRDKAFKA */
