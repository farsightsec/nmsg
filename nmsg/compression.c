/*
 * Copyright (c) 2023,2024 DomainTools LLC
 * Copyright (c) 2012, 2014-2017, 2021 by Farsight Security, Inc.
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

#include "private.h"

#include <zlib.h>
#if HAVE_LIBLZSTD
#include <zstd.h>
#endif
#if HAVE_LIBLZ4
#include <lz4.h>
#include <lz4hc.h>
#endif

#if HAVE_LIBLZ4
static nmsg_res
_nmsg_compress_lz4(const uint8_t *input, const size_t input_size,
		   uint8_t *output, size_t *output_size)
{
	char *lz4_bytes;
	int lz4_size;

	if (input_size > INT_MAX)
		return (nmsg_res_failure);

	lz4_size = LZ4_compressBound(input_size);
	if (lz4_size + sizeof(uint32_t) > *output_size)
		return (nmsg_res_failure);

	lz4_bytes = (char *) output + sizeof(uint32_t);

	lz4_size = LZ4_compress_default((const char *) input,
					lz4_bytes,
					(int) input_size,
					lz4_size);
	if (lz4_size == 0)
		return (nmsg_res_failure);

	*output_size = lz4_size + sizeof(uint32_t);

	/**
	 * Prefix the compressed LZ4 block with a 32-bit NBO integer
	 * specifying the size of the uncompressed block. This makes
	 * decompression much easier.
	 */
	store_net32(output, input_size);

	return (nmsg_res_success);
}

static nmsg_res
_nmsg_compress_lz4hc(const uint8_t *input, const size_t input_size,
		     uint8_t *output, size_t *output_size,
		     int zlevel)
{
	char *lz4_bytes;
	int lz4_size;

	if (input_size > INT_MAX)
		return (nmsg_res_failure);

	lz4_size = LZ4_compressBound(input_size);
	if (lz4_size + sizeof(uint32_t) > *output_size)
		return (nmsg_res_failure);

	if (zlevel < 0)
		zlevel = 0;

	lz4_bytes = (char *) output + sizeof(uint32_t);

	lz4_size = LZ4_compress_HC((const char *) input,
					lz4_bytes,
					(int) input_size,
					lz4_size,
					zlevel);
	if (lz4_size == 0)
		return (nmsg_res_failure);

	*output_size = lz4_size + sizeof(uint32_t);

	/**
	 * Prefix the compressed LZ4 block with a 32-bit NBO integer
	 * specifying the size of the uncompressed block. This makes
	 * decompression much easier.
	 */
	store_net32(output, input_size);

	return (nmsg_res_success);
}
#endif

#if HAVE_LIBLZSTD
static nmsg_res
_nmsg_compress_zstd(const uint8_t *input, const size_t input_size,
		    uint8_t *output, size_t *output_size,
		    int zlevel)
{
	size_t zstd_size;
	char *zstd_bytes;
	int minlevel;
#if ZSTD_VERSION_NUMBER >= 10400
	minlevel = ZSTD_minCLevel();
#else
	minlevel = 1;
#endif

	if (input_size > INT_MAX)
		return (nmsg_res_failure);

	if (zlevel < minlevel)
		zlevel = minlevel;
	else if (zlevel > ZSTD_maxCLevel())
		zlevel = ZSTD_maxCLevel();

	zstd_size = *output_size;
	zstd_bytes = (char *) output;

	zstd_size = ZSTD_compress(
		zstd_bytes,		/* dst */
		zstd_size,		/* dstCapacity */
		input,			/* src */
		input_size,		/* srcSize */
		zlevel	/* compressionLevel */
	);

	if (ZSTD_isError(zstd_size))
		return (nmsg_res_failure);

	*output_size = zstd_size;

	return (nmsg_res_success);
}
#endif

static nmsg_res
_nmsg_compress_zlib(const uint8_t *input, const size_t input_size,
		    uint8_t *output, size_t *output_size, int zlevel)
{
	int zret;
	z_stream zs = {
		.opaque	= Z_NULL,
		.zalloc	= Z_NULL,
		.zfree	= Z_NULL,
	};

	if (zlevel < Z_DEFAULT_COMPRESSION)
		zlevel = Z_NO_COMPRESSION;
	else if (zlevel > Z_BEST_COMPRESSION)
		zlevel = Z_BEST_COMPRESSION;

	zret = deflateInit(&zs, zlevel);
	assert(zret == Z_OK);

	zs.avail_in = input_size;
	zs.next_in = (uint8_t *) input;
	zs.avail_out = *output_size - sizeof(uint32_t);
	zs.next_out = output + sizeof(uint32_t);
	zret = deflate(&zs, Z_FINISH);
	assert(zret == Z_STREAM_END);
	assert(zs.avail_in == 0);

	zret = deflateEnd(&zs);
	if (zret != Z_OK)
		return (nmsg_res_failure);

	/* Store the original length at the start of the buffer. */
	store_net32(output, input_size);

	*output_size = zs.total_out + sizeof(uint32_t);

	return (nmsg_res_success);
}

#if HAVE_LIBLZ4
static nmsg_res
_nmsg_decompress_lz4(const uint8_t *input, const size_t input_size,
		     uint8_t **output, size_t *output_size)
{
	char *out_buf;
	uint32_t orig_len;
	int ret = 0;

	if (input_size > INT_MAX || input_size < sizeof(uint32_t))
		return (nmsg_res_failure);

	/**
	 * The first four bytes is a 32-bit NBO integer specifying
	 * the size of the uncompressed block.
	 */
	load_net32(input, &orig_len);

	out_buf = my_malloc(orig_len);

	ret = LZ4_decompress_safe((char *) input + sizeof(uint32_t),
				  out_buf,
				  input_size - sizeof(uint32_t),
				  orig_len);
	if (ret < 0) {
		free(out_buf);
		return (nmsg_res_failure);
	}

	*output = (uint8_t*) out_buf;
	*output_size = orig_len;

	return (nmsg_res_success);
}
#endif

#if HAVE_LIBLZSTD
static nmsg_res
_nmsg_decompress_zstd(const uint8_t *input, const size_t input_size,
		      uint8_t **output, size_t *output_size)
{
	char *out_buf;
	size_t orig_len;
	size_t ret = 0;

	if (input_size > INT_MAX)
		return (nmsg_res_failure);

	orig_len = ZSTD_getDecompressedSize(input, input_size);
	if (orig_len == 0)
		return (nmsg_res_failure);

	out_buf = my_malloc(orig_len);

	ret = ZSTD_decompress(
		out_buf,		/* dst */
		orig_len,		/* dstCapacity */
		input,			/* src */
		input_size		/* compressedSize */
	);

	if (ZSTD_isError(ret)) {
		free(out_buf);
		return (nmsg_res_failure);
	}

	*output = (uint8_t*) out_buf;
	*output_size = ret;

	return (nmsg_res_success);
}
#endif

static nmsg_res
_nmsg_decompress_zlib(const uint8_t *input, const size_t input_size,
		      uint8_t **output, size_t *output_size)
{
	uint8_t *out_buf;
	uint32_t orig_len;
	int zret;
	z_stream zs = {
		.avail_in	= 0,
		.next_in	= Z_NULL,
		.opaque		= Z_NULL,
		.zalloc		= Z_NULL,
		.zfree		= Z_NULL,
	};

	zret = inflateInit(&zs);
	assert(zret == Z_OK);

	/* Load size of original data at start of buffer. */
	load_net32(input, &orig_len);

	out_buf = my_malloc(orig_len);

	zs.avail_in = input_size - sizeof(uint32_t);
	zs.next_in = (uint8_t *) input + sizeof(uint32_t);
	zs.avail_out = orig_len;
	zs.next_out = out_buf;

	zret = inflate(&zs, Z_FINISH);	// TODO: Or Z_NO_FLUSH

	if (zret != Z_STREAM_END || zs.avail_out != 0) {
		free(out_buf);
		return (nmsg_res_failure);
	}

	inflateEnd(&zs);

	*output = out_buf;
	*output_size = zs.total_out;

	return (nmsg_res_success);
}

/* Returns default compression-level for compression-type. */
int
nmsg_default_compression_level(nmsg_compression_type ztype)
{
	int level;

	switch (ztype) {
	case NMSG_COMPRESSION_ZLIB:
		level = Z_DEFAULT_COMPRESSION;
		break;
#if HAVE_LIBLZSTD
	case NMSG_COMPRESSION_ZSTD:
		level = ZSTD_CLEVEL_DEFAULT;
		break;
#endif
#if HAVE_LIBLZ4
	case NMSG_COMPRESSION_LZ4HC:
		level = LZ4HC_CLEVEL_DEFAULT;
		break;
#endif
	default:
		level = 0;
		break;
	}

	return (level);
}

const char *
nmsg_compression_type_to_str(nmsg_compression_type ztype)
{
	switch (ztype) {
	case NMSG_COMPRESSION_NONE:
		return ("none");
	case NMSG_COMPRESSION_ZLIB:
		return ("zlib");
#if HAVE_LIBLZSTD
	case NMSG_COMPRESSION_ZSTD:
		return ("zstd");
#endif
#if HAVE_LIBLZ4
	case NMSG_COMPRESSION_LZ4:
		return ("lz4");
	case NMSG_COMPRESSION_LZ4HC:
		return ("lz4hc");
#endif
	default:
		return (NULL);
	}
}

nmsg_res
nmsg_compression_type_from_str(const char *s, nmsg_compression_type *t)
{
	if (strcasecmp(s, "none") == 0) {
		*t = NMSG_COMPRESSION_NONE;
		return (nmsg_res_success);
	}
	if (strcasecmp(s, "zlib") == 0) {
		*t = NMSG_COMPRESSION_ZLIB;
		return (nmsg_res_success);
	}
#if HAVE_LIBLZSTD
	if (strcasecmp(s, "zstd") == 0) {
		*t = NMSG_COMPRESSION_ZSTD;
		return (nmsg_res_success);
	}
#endif
#if HAVE_LIBLZ4
	if (strcasecmp(s, "lz4") == 0) {
		*t = NMSG_COMPRESSION_LZ4;
		return (nmsg_res_success);
	}
	if (strcasecmp(s, "lz4hc") == 0) {
		*t = NMSG_COMPRESSION_LZ4HC;
		return (nmsg_res_success);
	}
#endif

	return (nmsg_res_failure);
}

/*
 * Compresses data to a supplied output-buffer.
 *
 *    ztype - Compression-algorithm to use
 *   zlevel - Compression-level to use
 *   in_buf - Input buffer to compress
 *  in_size - Size, in bytes, of input buffer
 *  out_buf - Output buffer to hold compressed data
 * out_size - In/Out parameter, in bytes. On entry, the size of the output
 *            buffer. On return, the number of bytes in the output buffer.
 */
nmsg_res
nmsg_compress_level(nmsg_compression_type ztype, int zlevel,
		    const uint8_t *input, const size_t input_size,
		    uint8_t *output, size_t *output_size)
{
	switch (ztype) {
	case NMSG_COMPRESSION_NONE:
		return (nmsg_res_failure);
	case NMSG_COMPRESSION_ZLIB:
		return (_nmsg_compress_zlib(input, input_size, output, output_size, zlevel));
#if HAVE_LIBLZSTD
	case NMSG_COMPRESSION_ZSTD:
		return (_nmsg_compress_zstd(input, input_size, output, output_size, zlevel));
#endif
#if HAVE_LIBLZ4
	case NMSG_COMPRESSION_LZ4:
		return (_nmsg_compress_lz4(input, input_size, output, output_size));
	case NMSG_COMPRESSION_LZ4HC:
		return (_nmsg_compress_lz4hc(input, input_size, output, output_size, zlevel));
#endif
	default:
		return (nmsg_res_failure);
	}
}

/* Similar to above, except uses default compression level. */
nmsg_res
nmsg_compress(nmsg_compression_type ztype,
	      const uint8_t *input, const size_t input_size,
	      uint8_t *output, size_t *output_size)
{
	switch (ztype) {
	case NMSG_COMPRESSION_NONE:
		return (nmsg_res_failure);
	case NMSG_COMPRESSION_ZLIB:
		return (_nmsg_compress_zlib(input, input_size, output, output_size, Z_DEFAULT_COMPRESSION));
#if HAVE_LIBLZSTD
	case NMSG_COMPRESSION_ZSTD:
		return (_nmsg_compress_zstd(input, input_size, output, output_size, ZSTD_CLEVEL_DEFAULT));
#endif
#if HAVE_LIBLZ4
	case NMSG_COMPRESSION_LZ4:
		return (_nmsg_compress_lz4(input, input_size, output, output_size));
	case NMSG_COMPRESSION_LZ4HC:
		return (_nmsg_compress_lz4hc(input, input_size, output, output_size, LZ4HC_CLEVEL_DEFAULT));
#endif
	default:
		return (nmsg_res_failure);
	}
}

/* Decompress buffer, return in dynamically-allocated buffer, caller takes ownership. */
nmsg_res
nmsg_decompress(nmsg_compression_type ztype,
		const uint8_t *input, const size_t input_size,
		uint8_t **output, size_t *output_size)
{
	switch (ztype) {
	case NMSG_COMPRESSION_NONE:
		return (nmsg_res_failure);
	case NMSG_COMPRESSION_ZLIB:
		return (_nmsg_decompress_zlib(input, input_size, output, output_size));
#if HAVE_LIBLZSTD
	case NMSG_COMPRESSION_ZSTD:
		return (_nmsg_decompress_zstd(input, input_size, output, output_size));
#endif
#if HAVE_LIBLZ4
	case NMSG_COMPRESSION_LZ4:
		/* Fall through, LZ4 and LZ4HC use the same decompressor. */
	case NMSG_COMPRESSION_LZ4HC:
		return (_nmsg_decompress_lz4(input, input_size, output, output_size));
#endif
	default:
		return (nmsg_res_failure);
	}
}
