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

#ifndef NMSG_KAFKAIO_H
#define NMSG_KAFKAIO_H

/**
 * Forward declaration of Kafka context.
 */
typedef struct kafka_ctx * kafka_ctx_t;

/**
 * Destroy an NMSG Kafka context.
 *
 * \param[in] ctx an NMSG Kafka context to be destroyed.
 */
void kafka_ctx_destroy(kafka_ctx_t *ctx);

/**
 * Create a Kafka consumer.
 *
 * \param[in] addr NMSG Kafka address string in format proto:topic[#partition|%group_id]@broker[:port][,offset].
 * \param[in] timeout in milliseconds.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
kafka_ctx_t kafka_create_consumer(const char *addr, int timeout);

/**
 * Create a Kafka producer.
 *
 * \param[in] addr NMSG Kafka address string in format proto:topic[#partition|%group_id]@broker[:port].
 * \param[in] timeout in milliseconds.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
kafka_ctx_t kafka_create_producer(const char *addr, int timeout);

/**
 * Start reading a message from an NMSG Kafka consumer.
 * This read operation must be terminated with a call to kafka_read_finish().
 *
 * \param[in] ctx NMSG Kafka consumer context.
 * \param[out] buf double pointer that will receive the address of the next read message.
 * \param[out] len pointer to a variable to hold the received message size.
 *
 * \return nmsg_res_success on success and nmsg_res_failure otherwise.
 */
nmsg_res kafka_read_start(kafka_ctx_t ctx, uint8_t **buf, size_t *len);

/**
 * End reading a message from an NMSG Kafka consumer.
 *
 * \param[in] ctx NMSG Kafka consumer context.
 *
 * \return nmsg_res_success on success and nmsg_res_failure otherwise.
 */
nmsg_res kafka_read_finish(kafka_ctx_t ctx);

/**
 * Write a message to an NMSG Kafka producer.
 *
 * \param[in] ctx NMSG Kafka producer context.
 * \param[in] key pointer to an optional key to be sent (or NULL).
 * \param[in] key_len the size of the key to be written, in bytes.
 * \param[in] buf pointer to the data to be sent.
 * \param[in] buf_len the size of the data to be written, in bytes.
 *
 * \return nmsg_res_success on success and nmsg_res_failure otherwise.
 *
 * Note: Kafka takes ownership of the buffer passed as buf and destroys it
 * 	once the message is delivered. However, Kafka does NOT also take
 * 	ownership of the key pointer.
 */
nmsg_res kafka_write(kafka_ctx_t ctx,
		     const uint8_t *key, size_t key_len,
		     const uint8_t *buf, size_t buf_len);

/**
 * Signal Kafka to stop producing messages
 *
 * @param ctx NMSG Kafka (producer) context.
 */
void kafka_stop(kafka_ctx_t ctx);

/**
 * Flush Kafka producer queue
 *
 * @param ctx NMSG Kafka (producer) context.
 */
void kafka_flush(kafka_ctx_t ctx);

#endif /* NMSG_KAFKAIO_H */
