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

#ifndef NMSG_ALIAS_H
#define NMSG_ALIAS_H

/*! \file nmsg/alias.h
 * \brief Nmsg payload operator and group aliasing.
 *
 * Nmsg payloads have operator and group values associated with them. These
 * values are numeric on the wire to permit extensible assignment but may be
 * aliased to presentation forms.
 */

/**
 * Alias type.
 */
typedef enum {
	nmsg_alias_operator,	/*%< operator ID -> operator name */
	nmsg_alias_group	/*%< group ID -> group name */
} nmsg_alias_e;

/**
 * Look up an alias by key.
 *
 * \param ae alias type
 * 
 * \param key numeric ID
 *
 * \return presentation form name or NULL if not found
 */
const char *
nmsg_alias_by_key(nmsg_alias_e ae, unsigned key);

/**
 * Look up an alias by name.
 *
 * \param ae alias type
 * 
 * \param value presentation form name
 *
 * \return numeric ID
 */
unsigned
nmsg_alias_by_value(nmsg_alias_e ae, const char *value);

#endif /* NMSG_ALIAS_H */
