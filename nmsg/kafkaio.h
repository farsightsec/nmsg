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

#ifndef NMSG_KAFKAIO_H
#define NMSG_KAFKAIO_H

/**
 * Forward declaration fo Kafka context.
 */
typedef struct nmsg_kafka_ctx * nmsg_kafka_ctx_t;

/**
 * Destroy a NMSG Kafka context.
 *
 * \param[in] ctx a NMSG Kafka context to destroy.
 */
void nmsg_kafka_ctx_destroy(nmsg_kafka_ctx_t * ctx);

/**
 * Create a Kafka consumer.
 *
 * \param[in] addr NMSG Kafka address string in format topic#partition@broker{,offset}.
 * \param[in] timeout in milliseconds.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_kafka_ctx_t nmsg_kafka_create_consumer(const char *addr, int timeout);

/**
 * Create a Kafka producer.
 *
 * \param[in] addr NMSG Kafka address string in format topic#partition@broker{,offset}.
 * \param[in] timeout in milliseconds.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_kafka_ctx_t nmsg_kafka_create_producer(const char *addr, int timeout);

/**
 * Start reading a message with NMSG Kafka consumer.
 * One must call nmsr_kafka_read_end to finish reading
 *
 * \param[in] ctx NMSG Kafka consumer context.
 * \param[out] buf pointer to uint* buffer to read message into.
 * \param[out] len pointer to placeholder for message size.
 *
 * \return nmsg_res_success on success and nmsg_res_failure otherwise.
 */
nmsg_res nmsg_kafka_read_start(nmsg_kafka_ctx_t ctx, uint8_t **buf, size_t *len);

/**
 * End reading a message with NMSG Kafka consumer.
 *
 * \param[in] ctx NMSG Kafka consumer context.
 *
 * \return nmsg_res_success on success and nmsg_res_failure otherwise.
 */
nmsg_res nmsg_kafka_read_close(nmsg_kafka_ctx_t ctx);

/**
 * Write a message with NMSG Kafka producer.
 * One must call nmsr_kafka_read_end to finish reading
 *
 * \param[in] ctx NMSG Kafka consumer context.
 * \param[out] buf pointer to uint* buffer to read message into.
 * \param[out] len pointer to placeholder for message size.
 *
 * \return nmsg_res_success on success and nmsg_res_failure otherwise.
 */
nmsg_res nmsg_kafka_write(nmsg_kafka_ctx_t ctx, const uint8_t *buf, size_t len);

#endif //NMSG_KAFKAIO_H
