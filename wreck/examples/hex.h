#ifndef WDNS_EXAMPLES_HEX_H
#define WDNS_EXAMPLES_HEX_H

#include <stdbool.h>
#include <stdint.h>

bool hex_to_int(char hex, uint8_t *val);
bool hex_decode(const char *hex, uint8_t **raw, size_t *len);

#endif /* WDNS_EXAMPLES_HEX_H */
