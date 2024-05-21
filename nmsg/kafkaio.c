/*
 * Copyright (c) 2024 DomainTools LLC
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

/* Used when a partition is explicitly supplied */
#define KAFKA_GROUP_ID_NONE	-1
/* When no partition is named, create a consumer group */
#define KAFKA_GROUP_ID_DEFAULT	0

typedef enum {
	kafka_state_init = 1,
	kafka_state_ready,
	kafka_state_flush,
	kafka_state_break,
} kafka_state;

struct kafka_ctx {
	kafka_state		state;
	char			*topic_str;
	char			*broker;
	int			partition;
	int			group_id;
	bool			consumer;		/* consumer or producer */
	int			timeout;
	uint64_t 		counter_in;
	uint64_t 		counter_out;
	int64_t			offset;
	rd_kafka_t		*handle;
	rd_kafka_topic_t	*topic;
	rd_kafka_message_t	*message;
};

/* Forward. */

static bool _kafka_addr_init(kafka_ctx_t ctx, const char *addr);

static kafka_ctx_t _kafka_init_kafka(const char *addr, bool consumer, int timeout);

static void _kafka_flush(kafka_ctx_t ctx);

static void _kafka_ctx_destroy(kafka_ctx_t ctx);

static void _kafka_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque);

static void _kafka_delivery_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque);

static bool _kafka_config_set_option(rd_kafka_conf_t *config, const char *option, const char *value);

static bool _kafka_init_consumer(kafka_ctx_t ctx, rd_kafka_conf_t *config);

static bool _kafka_init_producer(kafka_ctx_t ctx, rd_kafka_conf_t *config);

/* Private. */

static bool
_kafka_addr_init(kafka_ctx_t ctx, const char *addr)
{
	char *pound, *at, *comma;
	ssize_t len;
	pound = strchr(addr, '#');
	at = strchr(addr, '@');
	comma = strchr(addr, ',');

	/* @ is mandatory */
	if (at == NULL) {
		_nmsg_dprintf(2, "%s: missing '@' in Kafka endpoint: %s\n", __func__, addr);
		return false;
	}

	ctx->group_id = KAFKA_GROUP_ID_NONE;

	if (pound != NULL)
		sscanf(pound + 1, "%d", &ctx->partition);
	else {
		ctx->group_id = KAFKA_GROUP_ID_DEFAULT;
		ctx->partition = RD_KAFKA_PARTITION_UA;
		pound = at;
	}

	len = pound - addr;
	if (len <= 0) {
		_nmsg_dprintf(2, "%s: invalid Kafka endpoint: %s\n", __func__, addr);
		return false;
	}

	ctx->topic_str = my_malloc(len + 1);
	strncpy(ctx->topic_str, addr,len);
	ctx->topic_str[len] = '\0';

	if (comma != NULL) {
		len = comma - at - 1;
		if (len <= 0) {
			_nmsg_dprintf(2, "%s: invalid Kafka endpoint: %s\n", __func__, addr);
			return false;
		}

		ctx->broker = my_malloc(len + 1);
		strncpy(ctx->broker, at + 1, len);
		ctx->broker[len] = '\0';
		++comma;

		if (strcasecmp(comma, "oldest") == 0)
			ctx->offset = RD_KAFKA_OFFSET_BEGINNING;
		else if (strcasecmp(comma, "newest") == 0)
			ctx->offset = RD_KAFKA_OFFSET_END;
		else if (isdigit(*comma) || (*comma == '-' && isdigit(*(comma+1))))
			sscanf(comma, "%ld", &ctx->offset);
		else {
			_nmsg_dprintf(2, "%s: invalid offset in Kafka endpoint: %s\n", __func__, comma);
			return false;
		}
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
	rd_kafka_conf_res_t res;

	res = rd_kafka_conf_set(config, option, value, errstr, sizeof(errstr));
	if (res != RD_KAFKA_CONF_OK) {
		_nmsg_dprintf(2, "%s: failed to set Kafka option %s = %s (err %d: %s)\n",
			__func__, option, value, res, errstr);
		return false;
	}

	return true;
}

static bool
_kafka_init_consumer(kafka_ctx_t ctx, rd_kafka_conf_t *config)
{
	char tmp[sizeof("4294967295")] = {0};
	char errstr[1024];
	rd_kafka_topic_partition_list_t *subscription;
	rd_kafka_conf_res_t res;
	rd_kafka_topic_conf_t *topic_conf;

	if (!_kafka_config_set_option(config, "enable.partition.eof", "true")) {
		rd_kafka_conf_destroy(config);
		return false;
	}

#if RD_KAFKA_VERSION >= 0x010600ff
	_kafka_config_set_option(config, "allow.auto.create.topics", "false");
#endif /* RD_KAFKA_VERSION > 0x010100ff */

	if (ctx->group_id != KAFKA_GROUP_ID_NONE) {
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
		_nmsg_dprintf(2, "%s: failed to create Kafka consumer: %s\n", __func__, errstr);
		return false;
	}
	/* Now handle owns the configuration */

	if (ctx->group_id != KAFKA_GROUP_ID_NONE) {
		rd_kafka_poll_set_consumer(ctx->handle);
		subscription = rd_kafka_topic_partition_list_new(1);
		if (subscription == NULL) {
			_nmsg_dprintf(2, "%s: failed to create partition list\n", __func__);
			return false;
		}

		rd_kafka_topic_partition_list_add(subscription, ctx->topic_str, ctx->partition);

		res = rd_kafka_subscribe(ctx->handle, subscription);

		rd_kafka_topic_partition_list_destroy(subscription);
		if (res != RD_KAFKA_CONF_OK) {
			_nmsg_dprintf(2, "%s: failed to subscribe to partition list\n", __func__);
			return false;
		}
	} else {
		/* Topic configuration */
		topic_conf = rd_kafka_topic_conf_new();
		if (topic_conf == NULL) {
			_nmsg_dprintf(2, "%s: failed to create topic configuration\n", __func__);
			return false;
		}

		/* Create topic */
		ctx->topic = rd_kafka_topic_new(ctx->handle, ctx->topic_str, topic_conf);
		if (ctx->topic == NULL) {
			_nmsg_dprintf(2, "%s: failed to create topic %s\n",
				__func__, ctx->topic_str);
			return false;
		}
	}

	ctx->state = kafka_state_ready;

	return true;
}

static bool
_kafka_init_producer(kafka_ctx_t ctx, rd_kafka_conf_t *config)
{
	char errstr[1024];
	rd_kafka_topic_conf_t *topic_conf;

	rd_kafka_conf_set_dr_msg_cb(config, _kafka_delivery_cb);

	/* Create Kafka producer handle */
	ctx->handle = rd_kafka_new(RD_KAFKA_PRODUCER, config, errstr, sizeof(errstr));
	if (ctx->handle == NULL) {
		rd_kafka_conf_destroy(config);
		_nmsg_dprintf(2, "%s: failed to create Kafka producer: %s\n", __func__, errstr);
		return false;
	}
	/* Now handle owns the configuration */

	/* Topic configuration */
	topic_conf = rd_kafka_topic_conf_new();
	if (topic_conf == NULL) {
		_nmsg_dprintf(2, "%s: failed to create topic configuration\n", __func__);
		return false;
	}

	/* Create topic */
	ctx->topic = rd_kafka_topic_new(ctx->handle, ctx->topic_str, topic_conf);
	if (ctx->topic == NULL) {
		_nmsg_dprintf(2, "%s: failed to create topic %s\n", __func__, ctx->topic_str);
		return false;
	}

	ctx->state = kafka_state_ready;
	return true;
}

static kafka_ctx_t
_kafka_init_kafka(const char *addr, bool consumer, int timeout)
{
	struct kafka_ctx *ctx;
	char tmp[sizeof("4294967295")] = {0};
	bool result;
	rd_kafka_conf_t *config;

	ctx = my_calloc(1, sizeof(struct kafka_ctx));

	ctx->state = kafka_state_init;
	ctx->timeout = timeout;
	ctx->consumer = consumer;

	if (!_kafka_addr_init(ctx, addr)) {
		_kafka_ctx_destroy(ctx);
		return NULL;
	}

	config = rd_kafka_conf_new();
	if (config == NULL) {
		_kafka_ctx_destroy(ctx);
		_nmsg_dprintf(2, "%s: failed to create Kafka configuration\n", __func__);
		return NULL;
	}

	rd_kafka_conf_set_opaque(config, ctx);
	rd_kafka_conf_set_error_cb(config, _kafka_error_cb);

	snprintf(tmp, sizeof(tmp), "%d", SIGIO);
	if (!_kafka_config_set_option(config, "internal.termination.signal", tmp) ||
	    !_kafka_config_set_option(config, "bootstrap.servers", ctx->broker)) {
		rd_kafka_conf_destroy(config);
		_kafka_ctx_destroy(ctx);
		return NULL;
	}

	result = ctx->consumer ? _kafka_init_consumer(ctx, config) :
		_kafka_init_producer(ctx, config);
	if (!result) {
		_kafka_ctx_destroy(ctx);
		return NULL;
	}

	return ctx;
}

static void
_kafka_flush(kafka_ctx_t ctx) {
	rd_kafka_resp_err_t res = RD_KAFKA_RESP_ERR_NO_ERROR;
	_nmsg_dprintf(3, "%s: Flushing Kafka queue\n", __func__);
	while (ctx->state != kafka_state_break &&
	       rd_kafka_outq_len(ctx->handle) > 0 &&
	       (res == RD_KAFKA_RESP_ERR_NO_ERROR || res == RD_KAFKA_RESP_ERR__TIMED_OUT))
		res = rd_kafka_flush(ctx->handle, ctx->timeout);
}

static void
_kafka_ctx_destroy(kafka_ctx_t ctx)
{
	if (ctx->state > kafka_state_init) {
		if (ctx->consumer) {
			if (ctx->group_id == KAFKA_GROUP_ID_NONE)	/* Stop consuming */
				rd_kafka_consume_stop(ctx->topic, ctx->partition);
			else
				rd_kafka_consumer_close(ctx->handle);

			rd_kafka_poll(ctx->handle, ctx->timeout);

			_nmsg_dprintf(3, "%s: Consumed %ld messages\n", "KafkaIO", ctx->counter_in);
		} else {
			_kafka_flush(ctx);

			_nmsg_dprintf(3, "%s: Produced %ld messages\n", "KafkaIO", ctx->counter_in);
			_nmsg_dprintf(3, "%s: Delivered %ld messages\n", "KafkaIO", ctx->counter_out);
			_nmsg_dprintf(3, "%s: Internal queue has %d messages \n", "KafkaIO", rd_kafka_outq_len(ctx->handle));
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
	kafka_ctx_t ctx = (kafka_ctx_t) opaque;
	rd_kafka_resp_err_t err_kafka = (rd_kafka_resp_err_t) err;

	switch(err_kafka) {
		case RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION:
		case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
		case RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE:
		/* At the moment treat any broker's error as fatal */
		default:
			ctx->state = kafka_state_break;
			_nmsg_dprintf(2, "%s: got Kafka error %d: %s\n", __func__, err, reason);
			break;
	}
}

static void
_kafka_delivery_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
	kafka_ctx_t ctx = (kafka_ctx_t) opaque;
	if (rkmessage == NULL)
		return;
	if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR) {
		_nmsg_dprintf(2, "%s: got Kafka error %d: %s\n", __func__, rkmessage->err,
			      rd_kafka_message_errstr(ctx->message));
		ctx->state = kafka_state_break;
		rd_kafka_yield(rk);
	}
	ctx->counter_out++;
}

/* Export. */

void
kafka_ctx_destroy(kafka_ctx_t *ctx)
{
	if (ctx != NULL && *ctx != NULL) {
		_kafka_ctx_destroy(*ctx);
		*ctx = NULL;
	}
}

nmsg_res
kafka_read_start(kafka_ctx_t ctx, uint8_t **buf, size_t *len)
{
	nmsg_res res = nmsg_res_success;
	if (buf == NULL || len == NULL || ctx == NULL ||
	    !ctx->consumer || ctx->state != kafka_state_ready)
		return nmsg_res_failure;

	*buf = NULL;
	*len = 0;

	if (ctx->group_id != KAFKA_GROUP_ID_NONE)
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
			ctx->counter_in++;
		} else {
			if (ctx->message->err == RD_KAFKA_RESP_ERR__PARTITION_EOF)
				res = nmsg_res_again;
			else {
				_kafka_error_cb(ctx->handle, ctx->message->err,
						rd_kafka_message_errstr(ctx->message), ctx);
				res = nmsg_res_failure;
			}

			/* Return error message to kafka */
			rd_kafka_message_destroy(ctx->message);
			ctx->message = NULL;
		}
	} else
		res = (errno == ETIMEDOUT ? nmsg_res_again : nmsg_res_failure);

	return res;
}

nmsg_res
kafka_read_finish(kafka_ctx_t ctx)
{
	if (ctx == NULL || !ctx->consumer || ctx->state != kafka_state_ready)
		return nmsg_res_failure;

	if (ctx->message != NULL) {
		/* Return message to rdkafka */
		rd_kafka_message_destroy(ctx->message);
		ctx->message = NULL;
	}

	return nmsg_res_success;
}

nmsg_res
kafka_write(kafka_ctx_t ctx, const uint8_t *buf, size_t len)
{
	int res;
	if (ctx == NULL || ctx->consumer || ctx->state != kafka_state_ready)
		return nmsg_res_failure;

	for(;;) {
		res = rd_kafka_produce(ctx->topic, ctx->partition, RD_KAFKA_MSG_F_FREE,
				       (void *) buf, len,	/* Payload and length */
				       NULL, 0,			/* Optional key and its length */
				       NULL);			/* Opaque data in message->_private. */

		/*
		 * Poll to handle delivery reports
		 * No timeout here as we want to
		 * trigger delivery, but not wait for it
		 * */
		rd_kafka_poll(ctx->handle, 0);
		if (res == 0) {
			ctx->counter_in++;
			break;
		} else if (errno != ENOBUFS) {
			_nmsg_dprintf(1, "%s: failed to produce Kafka message #%d: %s\n",
				__func__, errno, rd_kafka_err2str(errno));
			return nmsg_res_failure;
		}
	}
	return nmsg_res_success;
}

kafka_ctx_t
kafka_create_consumer(const char *addr, int timeout)
{
	kafka_ctx_t ctx;
	rd_kafka_resp_err_t err;

	if (addr == NULL)
		return NULL;

	ctx = _kafka_init_kafka(addr, true, timeout);
	if (ctx == NULL)
		return NULL;

	if (ctx->group_id == KAFKA_GROUP_ID_NONE) {
		/* Start consuming */
		if (rd_kafka_consume_start(ctx->topic, ctx->partition, ctx->offset) == -1) {
			err = rd_kafka_last_error();
			_kafka_ctx_destroy(ctx);
			_nmsg_dprintf(2, "%s: failed to start Kafka consumer (err %d: %s)\n",
				__func__, err, rd_kafka_err2str(err));
			return NULL;
		}
	}
	return ctx;
}

kafka_ctx_t
kafka_create_producer(const char *addr, int timeout)
{
	if (addr == NULL)
		return NULL;

	return _kafka_init_kafka(addr, false, timeout);
}

nmsg_input_t
nmsg_input_open_kafka_endpoint(const char *ep, int timeout)
{
	kafka_ctx_t ctx;

	ctx = kafka_create_consumer(ep, timeout);
	if (ctx == NULL)
		return NULL;

	return _input_open_kafka(ctx);
}

nmsg_output_t
nmsg_output_open_kafka_endpoint(const char *ep, size_t bufsz, int timeout)
{
	kafka_ctx_t ctx;

	ctx = kafka_create_producer(ep, timeout);
	if (ctx == NULL)
		return NULL;

	return _output_open_kafka(ctx, bufsz);
}

void
kafka_stop(kafka_ctx_t ctx)
{
	if (ctx == NULL && ctx->consumer)
		return;
	ctx->state = kafka_state_break;
}

void
kafka_flush(kafka_ctx_t ctx)
{
	if (ctx == NULL && ctx->consumer)
		return;
	_kafka_flush(ctx);
}

#else /* HAVE_LIBRDKAFKA */

/* Export. */

#include "kafkaio.h"

struct kafka_ctx {
	int state;
};

void
kafka_ctx_destroy(kafka_ctx_t *ctx __attribute__((unused)))
{
}

nmsg_res
kafka_read_start(kafka_ctx_t ctx __attribute__((unused)),
		 uint8_t **buf __attribute__((unused)),
		 size_t *len __attribute__((unused)))
{
	return nmsg_res_failure;
}

nmsg_res
kafka_read_finish(kafka_ctx_t ctx __attribute__((unused)))
{
	return nmsg_res_failure;
}

nmsg_res
kafka_write(kafka_ctx_t ctx __attribute__((unused)),
	    const uint8_t *buf __attribute__((unused)),
	    size_t len __attribute__((unused)))
{
	return nmsg_res_failure;
}

kafka_ctx_t
kafka_create_consumer(const char *addr __attribute__((unused)),
		      int timeout  __attribute__((unused)))
{
	return NULL;
}

kafka_ctx_t
kafka_create_producer(const char *addr __attribute__((unused)),
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
nmsg_output_open_kafka_endpoint(const char *ep __attribute__((unused)),
				size_t bufsz __attribute__((unused)),
				int timeout  __attribute__((unused)))
{
	return NULL;
}

void
kafka_stop(kafka_ctx_t ctx __attribute__((unused)))
{
}

void kafka_flush(kafka_ctx_t ctx __attribute__((unused)))
{
}

#endif /* HAVE_LIBRDKAFKA */
