#include "private.h"

wdns_msg_status
wdns_str_to_name(const char *str, wdns_name_t *name)
{
	const char *p;
	size_t label_len;
	ssize_t slen;
	uint8_t c, *oclen, *data;
	wdns_msg_status status;

	status = wdns_msg_err_parse_error;

	p = str;
	slen = strlen(str);

	if (slen == 1 && *p == '.') {
		name->len = 1;
		name->data = malloc(1);
		if (name->data == NULL)
			return (wdns_msg_err_malloc);
		name->data[0] = '\0';
		return (wdns_msg_success);
	}

	name->len = 0;
	name->data = malloc(WDNS_MAXLEN_NAME);
	if (name->data == NULL)
		return (wdns_msg_err_malloc);

	data = name->data;
	label_len = 0;
	oclen = data++;
	name->len++;

	for (;;) {
		c = *p++;
		label_len++;

		if (slen == 0) {
			/* end of input */
			if (name->len == WDNS_MAXLEN_NAME) {
				status = wdns_msg_err_name_overflow;
				goto out;
			}
			*oclen = --label_len;
			*data++ = '\0';
			name->len++;
			break;
		}

		if (name->len >= WDNS_MAXLEN_NAME) {
			status = wdns_msg_err_name_overflow;
			goto out;
		}

		if (c >= 'A' && c <= 'Z') {
			/* an upper case letter; downcase it */
			c |= 0x20;
			*data++ = c;
			name->len++;
		} else if (c == '\\' && !isdigit(*p)) {
			/* an escaped character */
			if (slen <= 0)
				goto out;
			*data++ = *p;
			name->len++;
			p++;
			slen--;
		} else if (c == '\\' && slen >= 3) {
			/* an escaped octet */
			char d[4];
			char *endptr = NULL;
			long int val;

			d[0] = *p++;
			d[1] = *p++;
			d[2] = *p++;
			d[3] = '\0';
			slen -= 3;
			if (!isdigit(d[0]) || !isdigit(d[1]) || !isdigit(d[2]))
				goto out;
			val = strtol(d, &endptr, 10);
			if (endptr != NULL && *endptr == '\0'
			    && val >= 0 && val <= 255)
			{
				uint8_t uval;
				
				uval = (uint8_t) val;
				*data++ = uval;
				name->len++;
			} else {
				goto out;
			}
		} else if (c == '\\') {
			/* should not occur */
			goto out;
		} else if (c == '.') {
			/* end of label */
			*oclen = --label_len;
			if (label_len == 0)
				goto out;
			oclen = data++;
			if (slen > 1)
				name->len++;
			label_len = 0;
		} else if (c != '\0') {
			*data++ = c;
			name->len++;
		}

		slen--;
	}

	return (wdns_msg_success);

out:
	free(name->data);
	return (status);
}
