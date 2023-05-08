#ifndef NMSG_JSON_H
#define NMSG_JSON_H

#include "strbuf.h"
#include "libmy/my_alloc.h"

static inline void
num_to_str(int num, int size, char * ptr) {
	int ndx = size - 1;

	while (size > 0) {
		int digit = num % 10;
		ptr[ndx] = '0' + digit;
		--ndx;
		--size;
		num /= 10;
	}
}

static inline size_t
vnum_to_str(uint64_t num, char *ptr) {
	uint64_t tmp = num;
	size_t ndx, left, ndigits = 0;

	do {
		ndigits++;
		tmp /= 10;
	} while (tmp != 0);

	left = ndigits;
	ndx = left - 1;
	while(left > 0) {
		int digit = num % 10;
		ptr[ndx] = '0' + digit;
		--ndx;
		--left;
		num = num/10;
	}

	ptr[ndigits] = '\0';

	return ndigits;
}

static inline void
declare_json_value(struct nmsg_strbuf *sb, const char *name, bool is_first) {
	char val[1024], *buf = val, *ptr = val;
	size_t nlen = strlen(name);

	if (nlen + 4 >= sizeof(val))
		ptr = buf = my_malloc(nlen + 5);

	if (!is_first) {
		*ptr++ = ',';
	}

	*ptr++ = '"';
	memcpy(ptr, name, nlen);
	ptr += nlen;
	*ptr++ = '"';
	*ptr++ = ':';

	nmsg_strbuf_append_str(sb, buf, ptr - buf);	// guaranteed success

	if (buf != val)
		free(buf);
}

static inline void
append_json_value_string(struct nmsg_strbuf *sb, const char *val, size_t vlen) {
	nmsg_strbuf_append_str(sb, "\"", 1);

	if (vlen == 0)
		vlen = strlen(val);

	nmsg_strbuf_append_str_json(sb, val, vlen);
	nmsg_strbuf_append_str(sb, "\"", 1);	// guaranteed success x 3
}

/* More performant variant for when we know data doesn't need to be escaped. */
static inline void
append_json_value_string_noescape(struct nmsg_strbuf *sb, const char *val, size_t vlen) {
	nmsg_strbuf_append_str(sb, "\"", 1);

	if (vlen == 0)
		vlen = strlen(val);

	nmsg_strbuf_append_str(sb, val, vlen);
	nmsg_strbuf_append_str(sb, "\"", 1);	// guaranteed success x 3
}

static inline void
append_json_value_int(struct nmsg_strbuf *sb, uint64_t val) {
	char numbuf[32];
	size_t nlen;

	nlen = vnum_to_str(val, numbuf);
	nmsg_strbuf_append_str(sb, numbuf, nlen);	// guaranteed succes
}

static inline void
append_json_value_bool(struct nmsg_strbuf *sb, bool val) {

	if (val)
		nmsg_strbuf_append_str(sb, "true", 4);
	else
		nmsg_strbuf_append_str(sb, "false", 5);	// guaranteed success
}

static inline void
append_json_value_double(struct nmsg_strbuf *sb, double val) {
	char dubbuf[64], *endp;
	size_t dlen;

	dlen = snprintf(dubbuf, sizeof(dubbuf), "%.18f", val);
	dubbuf[sizeof(dubbuf)-1] = 0;

	/* Trim possible trailing numerical zero padding */
	endp = dubbuf + dlen - 1;
	while (*endp != '\0' && endp > dubbuf) {
		if (*endp != '0' || *(endp-1) == '.')
			break;
		*endp-- = '\0';
		dlen--;
	}

	nmsg_strbuf_append_str(sb, dubbuf, dlen);	// guaranteed success
}

static inline void
append_json_value_null(struct nmsg_strbuf *sb) {
	nmsg_strbuf_append_str(sb, "null", 4);	// guaranteed success
}

#endif /* NMSG_JSON_H */