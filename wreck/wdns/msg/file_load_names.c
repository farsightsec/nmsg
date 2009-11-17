#include "private.h"

wdns_msg_status
wdns_file_load_names(const char *fname, wdns_callback_name cb, void *user)
{
	FILE *fp;
	char line[1280];
	wdns_msg_status status;
	wdns_name_t name;

	fp = fopen(fname, "r");
	if (fp == NULL)
		WDNS_ERROR(wdns_msg_err_failure);

	status = wdns_msg_success;
	memset(line, 0, sizeof(line));

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (line[0] == '\n' || line[0] == ' ' || line[0] == '#')
			continue;
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';
		status = wdns_str_to_name(line, &name);
		if (status != wdns_msg_success)
			break;
		cb(&name, user);
	}

	fclose(fp);
	return (status);
}
