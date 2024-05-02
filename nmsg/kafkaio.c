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

#define NMSG_KAFKA_GROUP_ID_NONE -1
#define NMSG_KAFKA_GROUP_ID_DEFAULT 0

typedef enum {
	NMSG_KAFKA_VOID = 0,
	NMSG_KAFKA_INITIALIZED,
	NMSG_KAFKA_RUNNING,
	NMSG_KAFKA_STOPPING,
	NMSG_KAFKA_STOPPED
} nmsg_kafka_state;

struct nmsg_kafka_ctx {
	nmsg_kafka_state state;	/* Kafka internal state */
	char *topic_str;
	char *broker;
	int partition;
	int group_id;
	bool consumer;
	int timeout;
	int64_t offset;
	rd_kafka_t *handle;
	rd_kafka_topic_t *topic;
	rd_kafka_message_t *message;
};

/* Macro */

#define _KAFKA_ERROR_FALSE(...) _kafka_error(__VA_ARGS__),false
#define _KAFKA_ERROR_NULL(...) _kafka_error(__VA_ARGS__),NULL

/* Forward. */

static void _kafka_error(const char * fmt,...);

static bool _kafka_addr_init(nmsg_kafka_ctx_t ctx, const char *addr);

static nmsg_kafka_ctx_t _kafka_init_kafka(const char *addr, bool consumer, int timeout);

static void _kafka_ctx_destroy(nmsg_kafka_ctx_t ctx);

static void _kafka_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque);

static bool _kafka_config_set_option(rd_kafka_conf_t *config, const char *option, const char *value);

static bool _kafka_init_consumer(nmsg_kafka_ctx_t ctx, rd_kafka_conf_t *config);

static bool _kafka_init_producer(nmsg_kafka_ctx_t ctx, rd_kafka_conf_t *config);

/* Private. */
static void
_kafka_error(const char *fmt,...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}

static bool
_kafka_addr_init(nmsg_kafka_ctx_t ctx, const char *addr)
{
	char *pound, *at, *comma;
	ssize_t len;
	pound = strchr(addr, '#');
	at = strchr(addr, '@');
	comma = strchr(addr, ',');

	/* @ is mandatory */
	if (at == NULL)
		return _KAFKA_ERROR_FALSE("Invalid address format, missing @ in %s",addr);

	ctx->group_id = NMSG_KAFKA_GROUP_ID_NONE;

	if (pound != NULL)
		sscanf(pound + 1, "%d", &ctx->partition);
	else {
		ctx->group_id = NMSG_KAFKA_GROUP_ID_DEFAULT;
		ctx->partition = RD_KAFKA_PARTITION_UA;
		pound = at;
	}

	len = pound - addr;
	ctx->topic_str = my_malloc(len + 1);
	strncpy(ctx->topic_str, addr,len);
	ctx->topic_str[len] = '\0';

	if (comma != NULL) {
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

static bool
_kafka_config_set_option(rd_kafka_conf_t *config, const char *option, const char *value) {
	char errstr[1024];
	rd_kafka_conf_res_t res = rd_kafka_conf_set(config, option, value, errstr, sizeof(errstr));

	if (res != RD_KAFKA_CONF_OK) {
		return _KAFKA_ERROR_FALSE("Failed to set %s = %s. [%d] - %s", option, value, res, errstr);
	}

	return true;
}

static bool
_kafka_init_consumer(nmsg_kafka_ctx_t ctx, rd_kafka_conf_t *config)
{
	char tmp[16];
	char errstr[1024];
	rd_kafka_topic_partition_list_t *subscription;
	rd_kafka_conf_res_t res;
	rd_kafka_topic_conf_t *topic_conf;

	if (!_kafka_config_set_option(config, "enable.partition.eof", "true") ||
		!_kafka_config_set_option(config, "allow.auto.create.topics", "false")) {
		rd_kafka_conf_destroy(config);
		return false;
	}

	if (ctx->group_id != NMSG_KAFKA_GROUP_ID_NONE) {
		snprintf(tmp, sizeof(tmp), "%i", ctx->group_id);
		if (!_kafka_config_set_option(config, "group.id", tmp)) {
			rd_kafka_conf_destroy(config);
			return false;
		}
	}

	/* Create Kafka consumer handle */
	ctx->handle = rd_kafka_new(RD_KAFKA_CONSUMER, config, errstr, sizeof(errstr));
	if (ctx->handle == NULL) {
		rd_kafka_conf_destroy(config);
		return _KAFKA_ERROR_FALSE("Failed to create Kafka consumer: %s", errstr);
	}
	/* Now handle owns the configuration */

	if (ctx->group_id != NMSG_KAFKA_GROUP_ID_NONE) {
		rd_kafka_poll_set_consumer(ctx->handle);
		subscription = rd_kafka_topic_partition_list_new(1);
		if (subscription == NULL)
			return _KAFKA_ERROR_FALSE("Failed to create partition list");

		rd_kafka_topic_partition_list_add(subscription, ctx->topic_str, ctx->partition);

		res = rd_kafka_subscribe(ctx->handle, subscription);

		rd_kafka_topic_partition_list_destroy(subscription);
		if (res != RD_KAFKA_CONF_OK)
			return _KAFKA_ERROR_FALSE("Failed to subscribe to partition list");
	} else {
		/* Topic configuration */
		topic_conf = rd_kafka_topic_conf_new();
		if (topic_conf == NULL)
			return _KAFKA_ERROR_FALSE("Failed to create topic configuration");

		/* Create topic */
		ctx->topic = rd_kafka_topic_new(ctx->handle, ctx->topic_str, topic_conf);
		if (ctx->topic == NULL)
			return _KAFKA_ERROR_FALSE("Failed to create topic %s", ctx->topic_str);
	}

	ctx->state = NMSG_KAFKA_INITIALIZED;
	return true;
}

static bool
_kafka_init_producer(nmsg_kafka_ctx_t ctx, rd_kafka_conf_t *config)
{
	char errstr[1024];
	rd_kafka_topic_conf_t *topic_conf;

	/* Create Kafka producer handle */
	ctx->handle = rd_kafka_new(RD_KAFKA_PRODUCER, config, errstr, sizeof(errstr));
	if (ctx->handle == NULL) {
		rd_kafka_conf_destroy(config);
		return _KAFKA_ERROR_FALSE("Failed to create Kafka producer: %s", errstr);
	}
	/* Now handle owns the configuration */

	/* Topic configuration */
	topic_conf = rd_kafka_topic_conf_new();
	if (topic_conf == NULL)
		return _KAFKA_ERROR_FALSE("Failed to create topic configuration");

	/* Create topic */
	ctx->topic = rd_kafka_topic_new(ctx->handle, ctx->topic_str, topic_conf);
	if (ctx->topic != NULL) {
		ctx->state = NMSG_KAFKA_RUNNING;
		return true;
	}
	return _KAFKA_ERROR_FALSE("Failed to create topic %s", ctx->topic_str);;
}

static nmsg_kafka_ctx_t
_kafka_init_kafka(const char *addr, bool consumer, int timeout)
{
	struct nmsg_kafka_ctx *ctx;
	char tmp[16];
	bool result;
	rd_kafka_conf_t *config;

	ctx = my_calloc(1, sizeof(struct nmsg_kafka_ctx));

	ctx->timeout = timeout;
	ctx->consumer = consumer;

	if (!_kafka_addr_init(ctx, addr)) {
		_kafka_ctx_destroy(ctx);
		return NULL;
	}

	config = rd_kafka_conf_new();
	if (config == NULL) {
		_kafka_ctx_destroy(ctx);
		return _KAFKA_ERROR_NULL("Failed to create Kafka configuration");
	}

	rd_kafka_conf_set_opaque(config, ctx);
	rd_kafka_conf_set_error_cb(config, _kafka_error_cb);

	snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	if (!_kafka_config_set_option(config, "internal.termination.signal", tmp) ||
		!_kafka_config_set_option(config, "bootstrap.servers", ctx->broker)) {
		rd_kafka_conf_destroy(config);
		_kafka_ctx_destroy(ctx);
		return NULL;
	}

	result = ctx->consumer ? _kafka_init_consumer(ctx, config) : _kafka_init_producer(ctx, config);
	if (!result) {
		_kafka_ctx_destroy(ctx);
		return NULL;
	}

	return ctx;
}

static void
_kafka_ctx_destroy(nmsg_kafka_ctx_t ctx)
{
	if (ctx->state > NMSG_KAFKA_VOID) {
		if (ctx->state == NMSG_KAFKA_RUNNING)
			ctx->state = NMSG_KAFKA_STOPPING;

		if (ctx->consumer) {
			if (ctx->group_id == NMSG_KAFKA_GROUP_ID_NONE)	/* Stop consuming */
				rd_kafka_consume_stop(ctx->topic, ctx->partition);
			else
				rd_kafka_consumer_close(ctx->handle);
			while(ctx->state != NMSG_KAFKA_STOPPED)
				rd_kafka_poll(ctx->handle, 0);
		}
		else {
			rd_kafka_resp_err_t res = RD_KAFKA_RESP_ERR_NO_ERROR;
			while (rd_kafka_outq_len(ctx->handle) > 0 && res == RD_KAFKA_RESP_ERR_NO_ERROR)
				res = rd_kafka_flush(ctx->handle, 10 * ctx->timeout);
		}
	}
	/* Destroy topic */
	if (ctx->topic != NULL)
		rd_kafka_topic_destroy(ctx->topic);

	/* Destroy handle */
	if (ctx->handle != NULL)
		rd_kafka_destroy(ctx->handle);

	if (ctx->topic_str != NULL)
		my_free(ctx->topic_str);

	if (ctx->broker != NULL)
		my_free(ctx->broker);

	my_free(ctx);
}

static void
_kafka_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque)
{
	nmsg_kafka_ctx_t ctx = (nmsg_kafka_ctx_t) opaque;
	rd_kafka_resp_err_t err_kafka = (rd_kafka_resp_err_t) err;
	switch(err_kafka) {
		case RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION:
		case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
		case RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE:
		/* At the moment treat any broker's error as fatal */
		default:
			ctx->state = NMSG_KAFKA_STOPPING;
			_kafka_error("%d - %s", err, reason);
	}
}

/* Export. */

void
nmsg_kafka_ctx_destroy(nmsg_kafka_ctx_t *ctx)
{
	if (ctx != NULL && *ctx != NULL) {
		_kafka_ctx_destroy(*ctx);
		*ctx = NULL;
	}
}

nmsg_res
nmsg_kafka_read_start(nmsg_kafka_ctx_t ctx, uint8_t **buf, size_t *len)
{
	if (buf == NULL || len == NULL ||
		ctx == NULL || !ctx->consumer)
		return nmsg_res_failure;

	*buf = NULL;
	*len = 0;
	ctx->state = NMSG_KAFKA_RUNNING;
	do {
		if (ctx->group_id != NMSG_KAFKA_GROUP_ID_NONE)
			ctx->message = rd_kafka_consumer_poll(ctx->handle, ctx->timeout);
		else {
			/* Poll for errors, etc. */
			rd_kafka_poll(ctx->handle, 0);

			ctx->message = rd_kafka_consume(ctx->topic, ctx->partition, ctx->timeout);
		}
		if (ctx->message != NULL) {
			if (ctx->message->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
				*buf = ctx->message->payload;
				*len = ctx->message->len;
			} else {
				if (ctx->message->err != RD_KAFKA_RESP_ERR__PARTITION_EOF)	/* Ignore EOF message, this loop end will handle the rest */
					_kafka_error_cb(ctx->handle, ctx->message->err, rd_kafka_message_errstr(ctx->message), ctx);
				/* Return error message to kafka */
				rd_kafka_message_destroy(ctx->message);
				ctx->message = NULL;
			}
		}
	} while(ctx->offset < 0 &&
			ctx->state == NMSG_KAFKA_RUNNING &&
			ctx->message == NULL);
	ctx->state = NMSG_KAFKA_STOPPED;

	return nmsg_res_success;
}

nmsg_res
nmsg_kafka_read_close(nmsg_kafka_ctx_t ctx)
{
	if (ctx == NULL || !ctx->consumer)
		return nmsg_res_failure;

	if (ctx->message != NULL)
		/* Return message to rdkafka */
		rd_kafka_message_destroy(ctx->message);

	return nmsg_res_success;
}

nmsg_res
nmsg_kafka_write(nmsg_kafka_ctx_t ctx, const uint8_t *buf, size_t len)
{
	int res;

	if (ctx == NULL || ctx->consumer || ctx->state != NMSG_KAFKA_RUNNING)
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

	if (addr == NULL)
		return NULL;

	ctx = _kafka_init_kafka(addr, true, timeout);
	if (ctx == NULL)
		return NULL;
	if (ctx->group_id == NMSG_KAFKA_GROUP_ID_NONE) {
		/* Start consuming */
		if (rd_kafka_consume_start(ctx->topic, ctx->partition, ctx->offset) == -1) {
			_kafka_ctx_destroy(ctx);
			return NULL;
		}
	}
	return ctx;
}

nmsg_kafka_ctx_t
nmsg_kafka_create_producer(const char *addr, int timeout)
{
	if (addr == NULL)
		return NULL;

	return _kafka_init_kafka(addr, false, timeout);
}

nmsg_input_t
nmsg_input_open_kafka_endpoint(const char *addr, int timeout)
{
	nmsg_kafka_ctx_t ctx;

	ctx = nmsg_kafka_create_consumer(addr, timeout);
	if (ctx == NULL)
		return NULL;

	return nmsg_input_open_kafka(ctx);
}

nmsg_output_t
nmsg_output_open_kafka_endpoint(const char *addr, size_t bufsz, int timeout)
{
	nmsg_kafka_ctx_t ctx;

	ctx = nmsg_kafka_create_producer(addr, timeout);
	if (ctx == NULL)
		return NULL;

	return nmsg_output_open_kafka(ctx, bufsz);
}

#else /* HAVE_LIBRDKAFKA */

/* Export. */

#include "kafkaio.h"

struct nmsg_kafka_ctx {
	int state;
};

void
nmsg_kafka_ctx_destroy(nmsg_kafka_ctx_t *ctx __attribute__((unused)))
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
