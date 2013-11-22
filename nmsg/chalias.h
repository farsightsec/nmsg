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

#ifndef NMSG_CHALIAS_H
#define NMSG_CHALIAS_H

/*! \file nmsg/chalias.h
 * \brief Nmsg channel aliases.
 */

/**
 * Lookup a channel alias.
 *
 * \param[in] ch Name of the channel.
 *
 * \param[out] alias Location to store an array of sockspecs.
 *
 * \return Number of aliases.
 */
int
nmsg_chalias_lookup(const char *ch, char ***alias);

/**
 * Free the memory allocated by nmsg_chalias_lookup().
 */
void
nmsg_chalias_free(char ***alias);

#endif /* NMSG_CHALIAS_H */
