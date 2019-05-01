/*
 * Copyright (c) 2008-2015 by Farsight Security, Inc.
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

#ifndef NMSG_IO_H
#define NMSG_IO_H

#include <nmsg/input.h>
#include <nmsg/output.h>

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
 * Add a user-specified filter function to the filter chain. See the
 * documentation for #nmsg_filter_message_fp for further details about the
 * semantics of the filter function itself.
 *
 * This function appends the specified filter to the end of an nmsg_io_t
 * object's list of filters.
 *
 * When an nmsg_io_t runs its processing loop, each message read from an input
 * stream is sequentially passed to each filter. If a filter returns the
 * verdict #nmsg_filter_message_verdict_DROP, the message will be immediately
 * destroyed with no further processing. The verdict
 * #nmsg_filter_message_verdict_ACCEPT causes the message to be accepted into
 * the output stream, bypassing any remaining filters in the filter chain, if
 * any. The verdict #nmsg_filter_message_verdict_DECLINED causes the message to
 * be passed to the next filter in the filter chain, if any.
 *
 * Filters in the filter chain are executed in the order that they were added
 * to the nmsg_io_t object with nmsg_io_add_filter() and
 * nmsg_io_add_filter_module().
 *
 * If the entire filter chain has been executed and all filters have returned
 * the verdict #nmsg_filter_message_verdict_DECLINED, the default action to
 * take is determined by the nmsg_io_t's filter policy, which can be set with
 * nmsg_io_set_filter_policy(). The default filter policy is
 * #nmsg_filter_message_verdict_ACCEPT.
 *
 * All filters must be added to the nmsg_io_t object before calling
 * nmsg_io_loop(). It is an unchecked runtime error for a caller to attempt to
 * modify the filter chain on an nmsg_io_t that is currently executing its
 * processing loop.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] fp User-specified function.
 *
 * \param[in] data User pointer to be passed to user function.
 *
 * \return #nmsg_res_success
 */
nmsg_res
nmsg_io_add_filter(nmsg_io_t io, nmsg_filter_message_fp fp, void *data);

/**
 * Add a filter module to the filter chain. This function instantiates an
 * nmsg_fltmod_t object with the specified 'name', 'param', and 'len_param'
 * values and appends the filter to the end of an nmsg_io_t object's list of
 * filters.
 *
 * Filter modules allow filter functions to be wrapped in external shared
 * objects, but they otherwise participate in the filter chain in the same way
 * that a filter function added with nmsg_io_add_filter() does.
 *
 * \see nmsg_io_add_filter()
 * \see nmsg_fltmod_init()
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] name Passed to nmsg_fltmod_init().
 * \param[in] param Passed to nmsg_fltmod_init().
 * \param[in] len_param Passed to nmsg_fltmod_init().
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure If creating the nmsg_fltmod_t object failed.
 */
nmsg_res
nmsg_io_add_filter_module(nmsg_io_t io, const char *name,
			  const void *param, const size_t len_param);

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
 * "Channels" are specified in the channel alias file, which is usually a file
 * named "nmsg.chalias" in the sysconfdir.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] chan Input channel name.
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
 * Add an nmsg XS input channel to an nmsg_io_t object.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] xs_ctx XS context object.
 *
 * \param[in] chan Input channel name.
 *
 * \param[in] user NULL or an input-specific user pointer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_parse_error
 * \return #nmsg_res_memfail
 */
nmsg_res
nmsg_io_add_input_xs_channel(nmsg_io_t io, void *xs_ctx, const char *chan, void *user);

/**
 * Add an nmsg input sockspec to an nmsg_io_t object. When nmsg_io_loop() is
 * called, one thread will be created for each input socket constituting the
 * sockspec to process input payloads.
 *
 * Sockspecs are strings in the form "<ADDRESS>/<PORTRANGE>" where <ADDRESS>
 * is an IPv4 or IPv6 address, and <PORTRANGE> is either a single port or a
 * contiguous, inclusive range of ports of the form "<PORT_START>..<PORT_END>".
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] sock Input channel.
 *
 * \param[in] user NULL or an input-specific user pointer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_parse_error
 * \return #nmsg_res_memfail
 */
nmsg_res
nmsg_io_add_input_sockspec(nmsg_io_t io, const char *sockspec, void *user);

/**
 * Add an NMSG file to an nmsg_io_t object.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] fname Name of NMSG file.
 *
 * \param[in] user NULL or an input-specific user pointer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_memfail
 */
nmsg_res
nmsg_io_add_input_fname(nmsg_io_t io, const char *fname, void *user);

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
 * Note that setting a count only guarantees that processing will terminate soon
 * after at least #count payloads have been received. It is possible for an
 * amount of inputs slightly greater than #count to be processed before the
 * nmsg_io_t instance stops.
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
 * Set the filter policy for the nmsg_io_t object's filter chain. If all
 * filters in the filter chain return #nmsg_filter_message_verdict_DECLINED for
 * a particular message, the filter policy determines the default policy action
 * to be applied to the message.
 *
 * If not explicitly set, the default is #nmsg_filter_message_verdict_ACCEPT.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] policy The filter policy to apply by default. Must be either
 *	#nmsg_filter_message_verdict_ACCEPT or
 *	#nmsg_filter_message_verdict_DROP.
 */
void
nmsg_io_set_filter_policy(nmsg_io_t io, const nmsg_filter_message_verdict policy);

/**
 * Configure the nmsg_io_t object to close inputs periodically, every #interval
 * seconds. The periodic closure is relative to the UNIX epoch, not the start of
 * nmsg_io_loop(). The actual closing may be delayed up to 0.5s
 * [NMSG_RBUF_TIMEOUT] after the interval's end.
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
 * Configure the nmsg_io_t object to randomize the initial second within the
 * interval where it closes inputs, rather than on the zeroth second
 * of the interval.
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] randomized Boolean flag.
 */
void
nmsg_io_set_interval_randomized(nmsg_io_t io, bool randomized);

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

/**
 * Emit counters related to payloads_in and payloads_out
 * These are normally emitted at process exit, but when using the
 * kicker option, it is useful to obtain these health related
 * metrics during the life time of the nmsgtool process (e.g. at
 * file rotation time)
 *
 * \param[in] io Valid nmsg_io_t object.
 *
 * \param[in] io Valid uint64_t object.
 *
 * \param[in] io Valid uint64_t object.
 *
 * \param[in] io Valid uint64_t object.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_io_get_stats(nmsg_io_t io, uint64_t *sum_in, uint64_t *sum_out, uint64_t *container_drops);


#endif /* NMSG_IO_H */
