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
