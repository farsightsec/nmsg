#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <nmsg.h>

static void
callback(nmsg_message_t msg, void *user __attribute__((unused))) {
	char *srcip;
	size_t len;
	nmsg_res res;

	res = nmsg_message_get_field(msg, "srcip", 0, (void **) &srcip, &len);
	if (res == nmsg_res_success) {
		char str_srcip[INET6_ADDRSTRLEN];

		if (len == 4) {
			if (inet_ntop(AF_INET, srcip, str_srcip, INET6_ADDRSTRLEN))
				printf("srcip=%s\n", str_srcip);
		} else if (len == 16) {
			if (inet_ntop(AF_INET6, srcip, str_srcip, INET6_ADDRSTRLEN))
				printf("srcip=%s\n", str_srcip);
		}
	}
	nmsg_message_destroy(&msg);
}

int
main(int argc, char **argv) {
	int i;
	nmsg_io_t io;
	nmsg_output_t output;
	nmsg_res res;

	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "unable to initialize libnmsg\n");
		return (EXIT_FAILURE);
	}

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <NMSGfile> [NMSGfile]...\n",
			argv[0]);
		return (EXIT_FAILURE);
	}

	io = nmsg_io_init();
	if (io == NULL) {
		fprintf(stderr, "nmsg_io_init() failed\n");
		return (EXIT_FAILURE);
	}

	for (i = 1; i < argc; i++) {
		int fd;
		nmsg_input_t input;

		fd = open(argv[i], O_RDONLY);
		if (fd < 0) {
			perror("open() failed:");
			return (EXIT_FAILURE);
		}

		input = nmsg_input_open_file(fd);
		if (input == NULL) {
			fprintf(stderr, "nmsg_input_open_file() failed\n");
			return (EXIT_FAILURE);
		}

		res = nmsg_io_add_input(io, input, NULL);
		if (res != nmsg_res_success) {
			fprintf(stderr, "nmsg_io_add_input() failed: %s\n",
				nmsg_res_lookup(res));
			return (EXIT_FAILURE);
		}
	}

	output = nmsg_output_open_callback(callback, NULL);
	if (output == NULL) {
		fprintf(stderr, "nmsg_output_open_callback() failed\n");
		return (EXIT_FAILURE);
	}

	res = nmsg_io_add_output(io, output, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "nmsg_io_add_output() failed: %s\n",
			nmsg_res_lookup(res));
		return (EXIT_FAILURE);
	}

	res = nmsg_io_loop(io);
	if (res != nmsg_res_success) {
		fprintf(stderr, "nmsg_io_loop() failed: %s\n",
			nmsg_res_lookup(res));
		return (EXIT_FAILURE);
	}

	nmsg_io_destroy(&io);

	return (EXIT_SUCCESS);
}
