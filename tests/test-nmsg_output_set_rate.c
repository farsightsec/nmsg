/*
 * Copyright (c) 2016 by Farsight Security, Inc.
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

#include <stdio.h>
#include "nmsg.h"

int main(void) {
	nmsg_output_t out1, out2;
	nmsg_rate_t rate1, rate2;

	out1 = nmsg_output_open_file(2, NMSG_WBUFSZ_ETHER);
	out2 = nmsg_output_open_file(2, NMSG_WBUFSZ_ETHER);

	rate1 = nmsg_rate_init(100,10);
	rate2 = nmsg_rate_init(1000,10);

	nmsg_output_set_rate(out1, rate1);
	nmsg_output_set_rate(out2, rate1);

	/**
	 * Earlier nmsg releases freed the previous
	 * rate associated with an output, which would
	 * cause a double free on the second call below.
	 */
	nmsg_output_set_rate(out1, rate2);
	nmsg_output_set_rate(out2, rate2);

	return 0;
}
