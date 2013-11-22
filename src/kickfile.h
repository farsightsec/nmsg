/*
 * Copyright (c) 2008 by Farsight Security, Inc.
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

#ifndef NMSGTOOL_KICKFILE_H
#define NMSGTOOL_KICKFILE_H

struct kickfile {
	char	*cmd;
	char	*curname;
	char	*basename;
	char	*tmpname;
	char	*suffix;
};

char *
kickfile_time(void);

void
kickfile_destroy(struct kickfile **);

void
kickfile_exec(struct kickfile *);

void
kickfile_rotate(struct kickfile *);

#endif
