/*
 * Copyright (c) 2009 by Farsight Security, Inc.
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

/* Import. */

#include "nmsg.h"
#include "private.h"

/* Globals. */

bool			_nmsg_global_autoclose = true;
int			_nmsg_global_debug;
struct nmsg_msgmodset *	_nmsg_global_msgmodset;

/* Statics. */

static int		_nmsg_initialized = 0;

/* Forward. */

static void _nmsg_fini(void);

/* Export. */

nmsg_res
nmsg_init(void) {
	char *msgmod_dir;

	assert(_nmsg_initialized == 0);

	msgmod_dir = getenv("NMSG_MSGMOD_DIR");
	if (msgmod_dir == NULL)
		msgmod_dir = NMSG_LIBDIR;

	_nmsg_global_msgmodset = _nmsg_msgmodset_init(msgmod_dir);
	if (_nmsg_global_msgmodset == NULL)
		return (nmsg_res_failure);
	atexit(_nmsg_fini);

	_nmsg_alias_init();

	_nmsg_initialized = 1;
	return (nmsg_res_success);
}

void
nmsg_set_autoclose(bool autoclose) {
	_nmsg_global_autoclose = autoclose;
}

void
nmsg_set_debug(int debug) {
	_nmsg_global_debug = debug;
}

/* Private. */

void
_nmsg_fini(void) {
	_nmsg_msgmodset_destroy(&_nmsg_global_msgmodset);
	_nmsg_alias_fini();
}
