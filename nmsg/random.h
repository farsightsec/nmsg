#ifndef NMSG_RANDOM_H

/*! \file nmsg/random.h
 * \brief Random number generator.
 */

#include <stdint.h>

nmsg_random_t
nmsg_random_init(void);

void
nmsg_random_destroy(nmsg_random_t *);

void
nmsg_random_buf(nmsg_random_t, uint8_t *, size_t);

uint32_t
nmsg_random_uint32(nmsg_random_t);

uint32_t
nmsg_random_uniform(nmsg_random_t, uint32_t upper_bound);

#endif /* NMSG_RANDOM_H */
