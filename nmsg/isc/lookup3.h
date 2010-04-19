#ifndef LOOKUP3_H
#define LOOKUP3_H

#include <stdint.h>

uint32_t hashword(const uint32_t *key, size_t length, uint32_t initval);
uint32_t hashlittle(const void *key, size_t length, uint32_t initval);
uint32_t hashbig(const void *key, size_t length, uint32_t initval);
void hashword2(const uint32_t *key, size_t length, uint32_t *pc, uint32_t *pb);
void hashlittle2(const void *key, size_t length, uint32_t *pc, uint32_t *pb);

#endif /* LOOKUP3_H */
