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
	char			*group_id;
	int			partition;
	bool			consumer;	/* consumer or producer */
	int			timeout;
	uint64_t		consumed;
	uint64_t		produced;
	uint64_t		delivered;
	uint64_t		dropped;
	int64_t			offset;
	rd_kafka_t		*handle;
	rd_kafka_topic_t	*topic;
	rd_kafka_message_t	*message;
	rd_kafka_queue_t 	*queue;
};

/* Forward. */

static bool _kafka_addr_init(kafka_ctx_t ctx, const char *addr);

static kafka_ctx_t _kafka_init_kafka(const char *addr, bool consumer, int timeout);

static void _kafka_flush(kafka_ctx_t ctx);

static void _kafka_ctx_destroy(kafka_ctx_t ctx);

static void _kafka_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque);

static void _kafka_delivery_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque);

static void _kafka_rebalance_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err,
				rd_kafka_topic_partition_list_t *partitions, void *opaque);

static void _kafka_log_cb(const rd_kafka_t *rk, int level, const char *fac, const char *buf);

static bool _kafka_config_set_option(rd_kafka_conf_t *config, const char *option, const char *value);

static bool _kafka_init_consumer(kafka_ctx_t ctx, rd_kafka_conf_t *config);

static bool _kafka_init_producer(kafka_ctx_t ctx, rd_kafka_conf_t *config);

static void _kafka_set_state(kafka_ctx_t ctx, const char *func, kafka_state state);

/* Private. */

static bool
_kafka_addr_init(kafka_ctx_t ctx, const char *addr)
{
	char *pound, *at, *comma, *percent;
	char str_part[16], str_off[64];
	ssize_t len;

	pound = strchr(addr, '#');
	at = strchr(addr, '@');
	comma = strchr(addr, ',');
	percent = strchr(addr, '%');

	/* @ is mandatory */
	if (at == NULL) {
		_nmsg_dprintf(2, "%s: missing '@' in Kafka endpoint: %s\n", __func__, addr);
		return false;
	}

	if (comma != NULL && comma < at) {
		_nmsg_dprintf(2, "%s: invalid offset position: %s\n", __func__, addr);
		return false;
	}

	ctx->group_id = NULL;

	if (pound != NULL) {
		if (pound > at) {
			_nmsg_dprintf(2, "%s: invalid partition position: %s\n", __func__, addr);
			return false;
		}
		if (percent != NULL) {
			_nmsg_dprintf(2, "%s: cannot use group and partition together: %s\n", __func__, addr);
			return false;
		}
		sscanf(pound + 1, "%d", &ctx->partition);
	} else {
		ctx->partition = RD_KAFKA_PARTITION_UA;
		if (percent != NULL) {
			if (percent > at) {
				_nmsg_dprintf(2, "%s: invalid group position: %s\n", __func__, addr);
				return false;
			}
			len = at - percent - 1;
			if (len <= 0) {
				_nmsg_dprintf(2, "%s: group id cannot be empty: %s\n", __func__, addr);
				return false;
			}
			ctx->group_id = strndup(percent + 1, len);
			pound = percent;
		} else
			pound = at;
	}

	len = pound - addr;
	if (len <= 0) {
		_nmsg_dprintf(2, "%s: invalid Kafka endpoint: %s\n", __func__, addr);
		return false;
	}

	ctx->topic_str = my_malloc(len + 1);
	strncpy(ctx->topic_str, addr, len);
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

		/* Oldest and newewst are applicable universally, but not numerical offsets. */
		if (strcasecmp(comma, "oldest") == 0)
			ctx->offset = RD_KAFKA_OFFSET_BEGINNING;
		else if (strcasecmp(comma, "newest") == 0)
			ctx->offset = RD_KAFKA_OFFSET_END;
		else if ((pound != NULL) && (isdigit(*comma) || (*comma == '-' && isdigit(*(comma+1)))))
			sscanf(comma, "%"PRIi64, &ctx->offset);
		else {
			_nmsg_dprintf(2, "%s: invalid offset in Kafka endpoint: %s\n", __func__, comma);
			return false;
		}

	} else {
		ctx->broker = my_malloc(strlen(at));
		strcpy(ctx->broker, at + 1);
		ctx->offset = RD_KAFKA_OFFSET_END;
	}

	if (ctx->offset == RD_KAFKA_OFFSET_BEGINNING)
		strcpy(str_off, "oldest");
	else if (ctx->offset == RD_KAFKA_OFFSET_END)
		strcpy(str_off, "newest");
	else
		snprintf(str_off, sizeof(str_off), "%"PRIi64, ctx->offset);

	if (ctx->partition == RD_KAFKA_PARTITION_UA)
		strcpy(str_part, "unassigned");
	else
		snprintf(str_part, sizeof(str_part), "%d", ctx->partition);

	_nmsg_dprintf(3, "%s: broker: %s, topic: %s, partition: %s, offset: %s (consumer group: %s)\n",
		__func__, ctx->broker, ctx->topic_str, str_part, str_off,
		(ctx->group_id == NULL ? "none" : ctx->group_id));

	return true;
}

static const char *
_kafka_state_to_str(kafka_state state)
{
	switch(state) {
	case kafka_state_init:
		return "init";
	case kafka_state_ready:
		return "ready";
	case kafka_state_flush:
		return "flush";
	case kafka_state_break:
		return "break";
	default:
		return "unknown";
	}

}

static void
_kafka_set_state(kafka_ctx_t ctx, const char *func, kafka_state state) {
	_nmsg_dprintf(3, "%s changing state from %s to %s\n", func,
		_kafka_state_to_str(ctx->state), _kafka_state_to_str(state));
	ctx->state = state;
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
	struct addrinfo *ai;
	struct addrinfo hints = {0};
	char errstr[1024], client_id[256], hostname[256];
	rd_kafka_topic_partition_list_t *subscription;
	rd_kafka_resp_err_t res;
	rd_kafka_topic_conf_t *topic_conf;

	if (!_kafka_config_set_option(config, "enable.partition.eof", "true")) {
		rd_kafka_conf_destroy(config);
		return false;
	}

#if RD_KAFKA_VERSION >= 0x010600ff
	_kafka_config_set_option(config, "allow.auto.create.topics", "false");
#endif /* RD_KAFKA_VERSION > 0x010100ff */
	gethostname(hostname, sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(hostname, NULL, &hints, &ai) == 0) {
		if (ai->ai_canonname != NULL) {
			strncpy(hostname, ai->ai_canonname, sizeof(hostname));
			hostname[sizeof(hostname) - 1] = '\0';
		}

		freeaddrinfo(ai);
	}

	if (snprintf(client_id, sizeof(client_id), "nmsgtool.%010u@%s",
			getpid(), hostname) == sizeof(client_id))
		client_id[sizeof(client_id) - 1 ] = '\0';

	_nmsg_dprintf(3, "%s: client ID: %s\n", __func__, client_id);
	if (!_kafka_config_set_option(config, "client.id", client_id)) {
		rd_kafka_conf_destroy(config);
		return false;
	}

	if (ctx->group_id != NULL) {
		const char *reset;

		if (!_kafka_config_set_option(config, "group.id", ctx->group_id)) {
			rd_kafka_conf_destroy(config);
			return false;
		}

		reset = ctx->offset == RD_KAFKA_OFFSET_END ? "latest" : "earliest";
		if (!_kafka_config_set_option(config, "auto.offset.reset", reset)) {
			rd_kafka_conf_destroy(config);
			return false;
		}

		rd_kafka_conf_set_rebalance_cb(config, _kafka_rebalance_cb);
	}

	/* Create Kafka consumer handle */
	ctx->handle = rd_kafka_new(RD_KAFKA_CONSUMER, config, errstr, sizeof(errstr));
	if (ctx->handle == NULL) {
		rd_kafka_conf_destroy(config);
		_nmsg_dprintf(2, "%s: failed to create Kafka consumer: %s\n", __func__, errstr);
		return false;
	}
	/* Now handle owns the configuration */

	if (ctx->group_id != NULL) {
		rd_kafka_poll_set_consumer(ctx->handle);
		subscription = rd_kafka_topic_partition_list_new(1);
		if (subscription == NULL) {
			_nmsg_dprintf(2, "%s: failed to create partition list\n", __func__);
			return false;
		}

		rd_kafka_topic_partition_list_add(subscription, ctx->topic_str, ctx->partition);

		res = rd_kafka_subscribe(ctx->handle, subscription);

		rd_kafka_topic_partition_list_destroy(subscription);
		if (res != RD_KAFKA_RESP_ERR_NO_ERROR) {
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

	_kafka_set_state(ctx, __func__, kafka_state_ready);

	return true;
}

static bool
_kafka_init_producer(kafka_ctx_t ctx, rd_kafka_conf_t *config)
{
	char errstr[1024];
	rd_kafka_topic_conf_t *topic_conf;

	rd_kafka_conf_set_dr_msg_cb(config, _kafka_delivery_cb);

	if (!_kafka_config_set_option(config, "enable.idempotence", "true")) {
		rd_kafka_conf_destroy(config);
		return false;
	}

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

	_kafka_set_state(ctx, __func__, kafka_state_ready);
	return true;
}

static kafka_ctx_t
_kafka_init_kafka(const char *addr, bool consumer, int timeout)
{
	struct kafka_ctx *ctx;
	uint8_t tmp_addr[16];
	char tmp[sizeof("4294967295")] = {0}, ip_str[INET6_ADDRSTRLEN + 2] = {0}, *pi;
	const char *af = "any";
	bool result;
	rd_kafka_conf_t *config;

	ctx = my_calloc(1, sizeof(struct kafka_ctx));

	_kafka_set_state(ctx, __func__, kafka_state_init);
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

	/*
	 * It is possible for an IP address to be surrounded by brackets.
	 * In the case of IPv6 this is necessary to distinguish the optional
	 * trailing port from the final octets of the represented address.
	 */
	if (ctx->broker[0] == '[') {
		strncpy(ip_str, ctx->broker + 1, sizeof(ip_str) - 1);
		pi = strchr(ip_str, ']');
	} else {
		strncpy(ip_str, ctx->broker, sizeof(ip_str) - 1);
		pi = strrchr(ip_str, ':');
	}

	if (pi != NULL)
		*pi = '\0';

	if (inet_pton(AF_INET, ip_str, tmp_addr) == 1)
		af = "v4";
	else if (inet_pton(AF_INET6, ip_str, tmp_addr) == 1)
		af = "v6";

	_kafka_config_set_option(config, "broker.address.family", af);

	rd_kafka_conf_set_opaque(config, ctx);
	rd_kafka_conf_set_error_cb(config, _kafka_error_cb);
	rd_kafka_conf_set_log_cb(config, _kafka_log_cb);

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
	_nmsg_dprintf(3, "%s: flushing Kafka queue\n", __func__);
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
			if (ctx->group_id == NULL)	/* Stop consuming */
				rd_kafka_consume_stop(ctx->topic, ctx->partition);
			else
				rd_kafka_consumer_close(ctx->handle);

			rd_kafka_poll(ctx->handle, ctx->timeout);

			_nmsg_dprintf(3, "%s: consumed %"PRIu64" messages\n", __func__, ctx->consumed);
		} else {
			_kafka_flush(ctx);

			_nmsg_dprintf(3, "%s: produced %"PRIu64" messages\n", __func__, ctx->produced);
			_nmsg_dprintf(3, "%s: delivered %"PRIu64" messages\n", __func__, ctx->delivered);
			_nmsg_dprintf(3, "%s: dropped %"PRIu64" messages\n", __func__, ctx->dropped);
			_nmsg_dprintf(3, "%s: internal queue has %d messages \n", __func__,
				rd_kafka_outq_len(ctx->handle));
		}
	}

	if (ctx->group_id != NULL)
		free(ctx->group_id);

	/* Destroy consumer queue (if any) */
	if (ctx->queue != NULL)
		rd_kafka_queue_destroy(ctx->queue);

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
	if (ctx == NULL) {
		_nmsg_dprintf(2, "%s: unexpected Kafka opaque is NULL", __func__);
		return;
	}
	switch (err_kafka) {
		/* Keep retrying on socket disconnect, brokers down and message timeout */
		case RD_KAFKA_RESP_ERR__TRANSPORT:
		case RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN:
		case RD_KAFKA_RESP_ERR__MSG_TIMED_OUT:
			_nmsg_dprintf(2, "%s: got Kafka error %d: %s\n", __func__, err, reason);
			break;
		case RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION:
		case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
		case RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE:
		/* At the moment treat any broker's error as fatal */
		default:
			_nmsg_dprintf(2, "%s: got Kafka error %d: %s\n", __func__, err, reason);
			_kafka_set_state(ctx, __func__, kafka_state_break);
			break;
	}
}

static void
_kafka_delivery_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
	kafka_ctx_t ctx = (kafka_ctx_t) opaque;
	if (rkmessage == NULL) {
		rd_kafka_yield(rk);
		return;
	}

	if (ctx == NULL) {
		_nmsg_dprintf(2, "%s: unexpected Kafka opaque is NULL", __func__);
		rd_kafka_yield(rk);
		return;
	}
	if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR) {
		int level = 2;
		if (rkmessage->err != RD_KAFKA_RESP_ERR__MSG_TIMED_OUT) {
			_kafka_set_state(ctx, __func__, kafka_state_break);
			rd_kafka_yield(rk);
		} else {
			ctx->dropped++;
			level = 4;
		}
		_nmsg_dprintf(level, "%s: got Kafka error %d: %s\n", __func__, rkmessage->err,
			      rd_kafka_err2str(rkmessage->err));

	} else
		ctx->delivered++;
}

static void
_kafka_log_cb(const rd_kafka_t *rk, int level, const char *fac, const char *buf)
{
	_nmsg_dprintf(3, "%s: %d: %s - %s\n", __func__, level, fac, buf);
}

static void
_kafka_rebalance_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err,
		    rd_kafka_topic_partition_list_t *partitions, void *opaque)
{
#if RD_KAFKA_VERSION >= 0x010600ff
	rd_kafka_error_t *resp_err = NULL;
#endif /* RD_KAFKA_VERSION >= 0x010600ff */
	rd_kafka_resp_err_t ret_err = RD_KAFKA_RESP_ERR_NO_ERROR;
	kafka_ctx_t ctx = (kafka_ctx_t) opaque;
	if (ctx == NULL) {
		_nmsg_dprintf(2, "%s: unexpected Kafka opaque is NULL", __func__);
		return;
	}

	switch (err) {
	case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
#if RD_KAFKA_VERSION >= 0x010600ff
		_nmsg_dprintf(3, "%s: partitions assigned (%s):\n", __func__, rd_kafka_rebalance_protocol(rk));
		if (!strcmp(rd_kafka_rebalance_protocol(rk), "COOPERATIVE"))
			resp_err = rd_kafka_incremental_assign(rk, partitions);
		else
#endif /* RD_KAFKA_VERSION >= 0x010600ff */
			ret_err = rd_kafka_assign(rk, partitions);
		break;
	case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
#if RD_KAFKA_VERSION >= 0x010600ff
		_nmsg_dprintf(3, "%s: partitions revoked (%s):\n", __func__, rd_kafka_rebalance_protocol(rk));
		if (!strcmp(rd_kafka_rebalance_protocol(rk), "COOPERATIVE"))
			resp_err = rd_kafka_incremental_unassign(rk, partitions);
		else
#endif /* RD_KAFKA_VERSION >= 0x010600ff */
			ret_err = rd_kafka_assign(rk, NULL);
		break;
        default:
		_nmsg_dprintf(2, "%s: failed: %s\n", __func__, rd_kafka_err2str(err));
		rd_kafka_assign(rk, NULL);
		break;
        }

	if (ret_err != RD_KAFKA_RESP_ERR_NO_ERROR)
		_nmsg_dprintf(2, "%s: partitions assign failure: %s\n", __func__, rd_kafka_err2str(ret_err));
#if RD_KAFKA_VERSION >= 0x010600ff
	else if (resp_err != NULL) {
		_nmsg_dprintf(2, "%s: incremental partitions assign failure: %s\n", __func__,
			rd_kafka_error_string(resp_err));
		rd_kafka_error_destroy(resp_err);
	}
#endif /* RD_KAFKA_VERSION >= 0x010600ff */
}

static bool
_kafka_consumer_start_queue(kafka_ctx_t ctx) {
	bool res = true;
	int ndx;
	rd_kafka_resp_err_t err;
	const rd_kafka_metadata_t *mdata;
	rd_kafka_metadata_topic_t * topic;

	for (ndx = 0; ndx < 10; ++ndx) {
		err = rd_kafka_metadata(ctx->handle, 0, ctx->topic, &mdata, NMSG_RBUF_TIMEOUT);
		if (err == RD_KAFKA_RESP_ERR_NO_ERROR)
			break;
	}
	if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
		_nmsg_dprintf(2, "%s: failed to get Kafka topic %s metadata (err %d: %s)\n",
			      __func__, ctx->topic_str, err, rd_kafka_err2str(err));
		return false;
	}

	if (mdata->topic_cnt != 1) {
		_nmsg_dprintf(2, "%s: received invalid metadata for topic %s\n", __func__, ctx->topic_str);
		res = false;
		goto out;
	}

	topic = &mdata->topics[0];

	if (topic->partition_cnt == 0) {
		_nmsg_dprintf(2, "%s: topic %s has no partitions\n", __func__, ctx->topic_str);
		res = false;
		goto out;
	}

	ctx->queue = rd_kafka_queue_new(ctx->handle);
	if (ctx->queue == NULL) {
		_nmsg_dprintf(2, "%s: failed to create consume queue for topic %s\n", __func__, ctx->topic_str);
		res = false;
		goto out;
	}

	for (ndx = 0; ndx < topic->partition_cnt; ++ndx) {
		if (rd_kafka_consume_start_queue(ctx->topic, ndx, ctx->offset, ctx->queue) == -1) {
			err = rd_kafka_last_error();
			_nmsg_dprintf(2, "%s: failed to start Kafka consumer (err %d: %s)\n",
				      __func__, err, rd_kafka_err2str(err));
			res = false;
			goto out;
		}
	}

out:
	rd_kafka_metadata_destroy(mdata);
	return res;
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

	if (ctx->group_id != NULL)
		ctx->message = rd_kafka_consumer_poll(ctx->handle, ctx->timeout);
	else {
		/* Poll for errors, etc. */
		rd_kafka_poll(ctx->handle, 0);
		if (ctx->queue == NULL)
			ctx->message = rd_kafka_consume(ctx->topic, ctx->partition, ctx->timeout);
		else
			ctx->message = rd_kafka_consume_queue(ctx->queue, ctx->timeout);
	}

	if (ctx->message != NULL) {
		if (ctx->message->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
			*buf = ctx->message->payload;
			*len = ctx->message->len;
			ctx->consumed++;
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
kafka_write(kafka_ctx_t ctx, const uint8_t *key, size_t key_len, const uint8_t *buf, size_t buf_len)
{
	int res;
	if (ctx == NULL || ctx->consumer || ctx->state != kafka_state_ready)
		return nmsg_res_failure;

	while (ctx->state == kafka_state_ready) {
		res = rd_kafka_produce(ctx->topic, ctx->partition, RD_KAFKA_MSG_F_FREE,
				       (void *) buf, buf_len,	/* Payload and length */
				       (void *) key, key_len,	/* Optional key and its length */
				       NULL);			/* Opaque data in message->_private. */

		if (res == 0) {
			ctx->produced++;
			break;
		} else if (errno != ENOBUFS) {
			_nmsg_dprintf(1, "%s: failed to produce Kafka message #%d: %s\n",
				__func__, errno, rd_kafka_err2str(errno));
			return nmsg_res_failure;
		}
		rd_kafka_poll(ctx->handle, ctx->timeout);
	}

	/* Poll with no timeout to trigger delivery reports without waiting */
	rd_kafka_poll(ctx->handle, 0);
	return ((ctx->state == kafka_state_ready) ? nmsg_res_success : nmsg_res_failure);
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

	/* Either a partition # or no consumer group ID has been supplied. */
	if (ctx->topic != NULL) {
		if (ctx->partition != RD_KAFKA_PARTITION_UA) {
			/* Start consuming */
			if (rd_kafka_consume_start(ctx->topic, ctx->partition, ctx->offset) == -1) {
				err = rd_kafka_last_error();
				_kafka_ctx_destroy(ctx);
				_nmsg_dprintf(2, "%s: failed to start Kafka consumer (err %d: %s)\n",
					      __func__, err, rd_kafka_err2str(err));
				return NULL;
			}
		} else if (!_kafka_consumer_start_queue(ctx)) {		/* no partition # */
			_kafka_ctx_destroy(ctx);
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
nmsg_input_open_kafka_endpoint(const char *ep)
{
	kafka_ctx_t ctx;

	ctx = kafka_create_consumer(ep, NMSG_RBUF_TIMEOUT);
	if (ctx == NULL)
		return NULL;

	return _input_open_kafka(ctx);
}

nmsg_output_t
nmsg_output_open_kafka_endpoint(const char *ep, size_t bufsz)
{
	kafka_ctx_t ctx;

	ctx = kafka_create_producer(ep, NMSG_RBUF_TIMEOUT);
	if (ctx == NULL)
		return NULL;

	return _output_open_kafka(ctx, bufsz);
}

void
kafka_stop(kafka_ctx_t ctx)
{
	if (ctx == NULL && ctx->consumer)
		return;
	_kafka_set_state(ctx, __func__, kafka_state_break);
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
	    const uint8_t *key __attribute__((unused)),
	    size_t key_len __attribute__((unused)),
	    const uint8_t *buf __attribute__((unused)),
	    size_t buf_len __attribute__((unused)))
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
nmsg_input_open_kafka_endpoint(const char *ep __attribute__((unused)))
{
	return NULL;
}

nmsg_output_t
nmsg_output_open_kafka_endpoint(const char *ep __attribute__((unused)),
				size_t bufsz __attribute__((unused)))
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
