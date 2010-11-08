/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef NMSG_IO_H
#define NMSG_IO_H

/*! \file nmsg/io.h
 * \brief Multi-threaded nmsg I/O processing.
 *
 * nmsg_io_t objects handle the multiplexing of NMSG data between nmsg_input_t
 * and nmsg_output_t objects. Callers should initialize at least one input and
 * at least one output and add them to an nmsg_io_t object before calling
 * nmsg_io_loop().
 *
 * Striping and mirroring of input payloads to individual outputs is supported.
 * Striping is the default mode. Mirroring imposes the overhead of a per-output
 * copy for each input payload.
 *
 * <b>MP:</b>
 *	\li One thread is created to handle reading from each input.
 *	nmsg_io_loop() will block until all data has been processed, but callers
 *	should take care not to touch an nmsg_io_t object (or any of its
 *	constituent input or output objects) asychronously while nmsg_io_loop()
 *	is executing, with the exception of nmsg_io_breakloop() which may be
 *	called to abort the loop.
 */

#include <stdbool.h>

#include <nmsg/input.h>
#include <nmsg/output.h>
#include <nmsg.h>

/**
 * Type of a close event notification.
 */
typedef enum {
	nmsg_io_close_type_eof,		/*%< end of file */
	nmsg_io_close_type_count,	/*%< payload count reached */
	nmsg_io_close_type_interval	/*%< interval elapsed */
} nmsg_io_close_type;

/**
 * Type of the stream associated with a close event.
 */
typedef enum {
	nmsg_io_io_type_input,		/*%< close event input */
	nmsg_io_io_type_output		/*%< close event output */
} nmsg_io_io_type;

/**
 * Output behavior when multiple outputs are present.
 */
typedef enum {
	nmsg_io_output_mode_stripe,	/*%< stripe payloads across output */
	nmsg_io_output_mode_mirror	/*%< mirror payloads across output */
} nmsg_io_output_mode;

/**
 * Structure for passing information about a close event between the nmsg_io
 * processing loop and the original caller. In order to receive these close
 * events, the caller must specify a callback function with
 * nmsg_io_set_close_fp().
 *
 * #nmsg_io_close_type_eof is sent for both inputs and outputs. The callback
 * function is responsible for closing the input or output.
 *
 * #nmsg_io_close_type_count is sent for outputs if nmsg_io_set_count() has been
 * called and a non-NULL user parameter was passed to nmsg_io_add_input() or
 * nmsg_io_add_output().
 *
 * #nmsg_io_close_type_interval is sent for inputs if nmsg_io_set_interval() has
 * been called and a non-NULL user parameter was passed to nmsg_io_add_input()
 * or nmsg_io_add_output().
 *
 * The 'user' field of this struct is associated with the input or output object
 * and is determined by the caller's 'user' parameter to the nmsg_io_add_input()
 * or nmsg_io_add_output() functions.
 *
 * If an output reaches a count or interval limit, the callback function
 * is responsible for closing and optionally re-opening the output. The callee
 * may also ignore this close event.
 *
 * nmsg_io supports the <b>reopening</b> of outputs after a certain number of
 * payloads have been processed or a certain time interval has elapsed. The
 * caller must call nmsg_io_add_input() or nmsg_io_add_output() with a non-NULL
 * user parameter, set the close event callback function with
 * nmsg_io_set_close_fp(), and set a stop condition with nmsg_io_set_count() or
 * nmsg_io_set_interval(). When the close event function is then called with
 * #nmsg_io_close_type_count or #nmsg_io_close_type_interval, it should reopen the
 * output and pass it back to nmsg_io via the 'output' pointer in the close
 * event structure.
 */
struct nmsg_io_close_event {
	union {
		nmsg_input_t	*input;		/*%< pointer to input stream */
		nmsg_output_t	*output;	/*%< pointer to output stream */
	};
	union {
		nmsg_input_type	input_type;	/*%< type of 'input' field */
		nmsg_output_type output_type;	/*%< type of 'output' field */
	};
	nmsg_io_t		io;	    /*%< this nmsg_io loop */
	nmsg_io_io_type		io_type;    /*%< whether 'input' or 'output' */
	nmsg_io_close_type	close_type; /*%< why the stream was closed */
	void			*user;	    /*%< caller-provided user pointer */
};

/**
 * Function for handling close event notifications.
 *
 * \param[in,out] ce Close event
 */
typedef void (*nmsg_io_close_fp)(struct nmsg_io_close_event *ce);

/**
 * Optional user-specified function to be run at thread start or thread stop.
 */
typedef void (*nmsg_io_user_fp)(unsigned threadno, void *user);

/**
 * Initialize a new nmsg_io_t object.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_io_t
nmsg_io_init(void);

/**
 * Add an nmsg input to an nmsg_io_t object. When nmsg_io_loop() is called, one
 * thread will be created for each input to process input payloads.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] input Valid nmsg_input_t object.
 *
 * \param[in] user NULL or an input-specific user pointer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 */
nmsg_res
nmsg_io_add_input(nmsg_io_t io, nmsg_input_t input, void *user);

/**
 * Add an nmsg input channel to an nmsg_io_t object. When nmsg_io_loop() is
 * called, one thread will be created for each input socket constituting the
 * channel to process input payloads.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] chan Input channel.
 *
 * \param[in] user NULL or an input-specific user pointer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_parse_error
 * \return #nmsg_res_memfail
 */
nmsg_res
nmsg_io_add_input_channel(nmsg_io_t io, const char *chan, void *user);

/**
 * Add an nmsg output to an nmsg_io_t object. When nmsg_io_loop() is called, the
 * input threads will cycle over and write payloads to the available outputs.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] output Valid nmsg_output_t object.
 *
 * \param[in] user NULL or an output-specific user pointer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 */
nmsg_res
nmsg_io_add_output(nmsg_io_t io, nmsg_output_t output, void *user);

/**
 * Begin processing the data specified by the configured inputs and
 * outputs.
 *
 * One processing thread is created for each input. nmsg_io_loop() does not
 * return until these threads finish and are destroyed.
 *
 * Only nmsg_io_breakloop() may be called asynchronously while nmsg_io_loop() is
 * executing.
 *
 * nmsg_io_loop() invalidates an nmsg_io_t object. nmsg_io_destroy() should then
 * be called.
 *
 * \param[in] io valid nmsg_io_t object.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_io_loop(nmsg_io_t io);

/**
 * Force a currently executing nmsg_io_loop() to stop looping and return.
 *
 * Since nmsg_io_loop() is a blocking call, nmsg_io_breakloop() must be called
 * asynchronously.
 *
 * This function is safe to call inside a signal handler.
 *
 * \param[in] io Valid and currently processing nmsg_io_t object.
 */
void
nmsg_io_breakloop(nmsg_io_t io);

/**
 * Deallocate the resources associated with an nmsg_io_t object.
 *
 * \param[in] io Pointer to an nmsg_io_t object.
 */
void
nmsg_io_destroy(nmsg_io_t *io);

/**
 * Get the number of inputs bound to the nmsg_io_t object.
 *
 * \return Number of inputs.
 */
unsigned
nmsg_io_get_num_inputs(nmsg_io_t io);

/**
 * Get the number of outputs bound to the nmsg_io_t object.
 *
 * \return Number of outputs.
 */
unsigned
nmsg_io_get_num_outputs(nmsg_io_t io);

/**
 * Set the close event notification function associated with an nmsg_io_t
 * object.
 *
 * The provided function will only be called at EOF on an input or output
 * stream, unless nmsg_io_set_count() or nmsg_io_set_interval() are used to
 * specify conditions when an input stream should be closed.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] close_fp Close event notification function. It must be reentrant.
 */
void
nmsg_io_set_close_fp(nmsg_io_t io, nmsg_io_close_fp close_fp);

/**
 * Set a user-specified function to be called in each thread after the
 * thread starts.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] user_fp User-specified function.
 *
 * \param[in] user User pointer to be passed to user function.
 */
void
nmsg_io_set_atstart_fp(nmsg_io_t io, nmsg_io_user_fp user_fp, void *user);

/**
 * Set a user-specified function to be called in each thread before the
 * thread exits.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] user_fp User-specified function.
 *
 * \param[in] user User pointer to be passed to user function.
 */
void
nmsg_io_set_atexit_fp(nmsg_io_t io, nmsg_io_user_fp user_fp, void *user);

/**
 * Configure the nmsg_io_t object to close inputs after processing a certain
 * non-zero number of payloads.
 *
 * If the 'user' pointer associated with an output stream is non-NULL the close
 * event notification function must be set, and this function must reopen the
 * stream. If the 'user' pointer is NULL, nmsg_io processing will be shut down.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] count Integer > 0.
 */
void
nmsg_io_set_count(nmsg_io_t io, unsigned count);

/**
 * Set the debug level for an nmsg_io_t object. Debug levels >= 0 will cause
 * debugging information to be logged to stderr.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] debug Debug level.
 */
void
nmsg_io_set_debug(nmsg_io_t io, int debug);

/**
 * Configure the nmsg_io_t object to close inputs after processing for a set
 * amount of time.
 *
 * If the 'user' pointer associated with an output stream is non-NULL the close
 * event notification function must be set, and this function must reopen the
 * stream. If the 'user' pointer is NULL, nmsg_io processing will be shut down.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] interval Positive number of seconds.
 */
void
nmsg_io_set_interval(nmsg_io_t io, unsigned interval);

/**
 * Set the output mode behavior for an nmsg_io_t object. Nmsg payloads received
 * from inputs may be striped across available outputs (the default), or
 * mirrored across all available outputs.
 *
 * Since nmsg_io must synchronize access to individual outputs, the mirrored
 * output mode will limit the amount of parallelism that can be achieved.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] output_mode #nmsg_io_output_mode_stripe or
 *	#nmsg_io_output_mode_mirror.
 */
void
nmsg_io_set_output_mode(nmsg_io_t io, nmsg_io_output_mode output_mode);

#endif /* NMSG_IO_H */
