/*
 * Copyright (c) 2023,2024 DomainTools LLC
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

#ifndef _COMPRESSION_H_
#define _COMPRESSION_H_

/*
 * Note: do not conditionally define these compression types by #if
 * HAVE_xx macros because we need to parse and complain if we find an
 * unsupported compression level.  See _input_nmsg_extract_header().
 *
 * These are used as an array index -- keep numbers small and adjacent
 */
typedef enum {
	NMSG_COMPRESSION_NONE = 0,
	NMSG_COMPRESSION_ZLIB = 1,
	NMSG_COMPRESSION_ZSTD = 2,
	NMSG_COMPRESSION_LZ4 = 3,
	NMSG_COMPRESSION_LZ4HC = 4,
} nmsg_compression_type;

extern const char *nmsg_compression_type_to_str(nmsg_compression_type compression_type);

extern nmsg_res nmsg_compression_type_from_str(const char *s, nmsg_compression_type *t);

extern nmsg_res nmsg_compress(nmsg_compression_type compression_type,
			      const uint8_t *input, const size_t input_size,
			      uint8_t *output, size_t *output_size);

extern nmsg_res nmsg_compress_level(nmsg_compression_type compression_type, int compression_level,
				    const uint8_t *input, const size_t input_size,
				    uint8_t *output, size_t *output_size);

extern nmsg_res nmsg_decompress(nmsg_compression_type compression_type,
				const uint8_t *input, const size_t input_size,
				uint8_t **output, size_t *output_size);

extern int nmsg_default_compression_level(nmsg_compression_type);

extern bool nmsg_compression_set_clib(int ztype);

#endif
