typedef enum {
	wreck_success,
	wreck_err_invalid_compression_pointer,
	wreck_err_invalid_length_octet,
	wreck_err_invalid_opcode,
	wreck_err_invalid_rcode,
	wreck_err_len,
	wreck_err_malloc,
	wreck_err_name_len,
	wreck_err_name_overflow,
	wreck_err_out_of_bounds,
	wreck_err_overflow,
	wreck_err_parse_error,
	wreck_err_qdcount,
	wreck_err_unknown_opcode,
	wreck_err_unknown_rcode,
} wreck_status;

#include <wreck/dns_constants.h>
#include <wreck/msg.h>

#define WRECK_ERROR(val) do { \
	VERBOSE(#val "\n"); \
	return (val); \
} while(0)

/**
 * Advance pointer p by sz bytes and update len.
 */
#define WRECK_BUF_ADVANCE(p, len, sz) do { \
	p += sz; \
	len -= sz; \
} while (0)

/**
 * Read an 8 bit integer.
 */
#define WRECK_BUF_GET8(dst, src) do { \
	memcpy(&dst, src, 1); \
	src++; \
} while (0)

/**
 * Read a 16 bit integer.
 */
#define WRECK_BUF_GET16(dst, src) do { \
	memcpy(&dst, src, 2); \
	dst = ntohs(dst); \
	src += 2; \
} while (0)

/**
 * Read a 32 bit integer.
 */
#define WRECK_BUF_GET32(dst, src) do { \
	memcpy(&dst, src, 4); \
	dst = ntohl(dst); \
	src += 4; \
} while (0)
