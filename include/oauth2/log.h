#ifndef _OAUTH2_LOG_H_
#define _OAUTH2_LOG_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2025 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

/**
 * @file log.h
 * @brief Logging: log contexts, sinks and the level-checked log macros.
 *
 * Every non-trivial function in the library takes an oauth2_log_t as
 * its first parameter and logs through the oauth2_error() ...
 * oauth2_trace2() macros, which capture the source file, line and
 * function of the call site. A log context is a list of sinks: each
 * sink carries its own level, a callback that emits one formatted
 * message and an opaque context for that callback - the server_rec or
 * request_rec to log against in the Apache binding, the ngx_log_t in
 * the NGINX binding. A message is delivered to every sink whose level
 * is at or above the level of the message. The oauth2_log_sink_stderr
 * and oauth2_log_sink_stdout built-in sinks print to the standard
 * streams.
 *
 * A log context is normally obtained from oauth2_init() (util.h),
 * which also initializes the global state of the library, and
 * released with oauth2_shutdown(); oauth2_log_init() and
 * oauth2_log_free() create and free a bare context, as the server
 * bindings do for each request.
 */

/**
 * @brief Storage class for the data symbols that cross the library
 *        boundary.
 *
 * A Windows DLL exports data only when its declaration says so, and a
 * consumer resolves that data only through __declspec(dllimport);
 * functions need neither, the linker binds them through the import
 * library. OAUTH2_EXPORTS is defined when compiling liboauth2 itself,
 * OAUTH2_STATIC when its objects are linked in directly. Everywhere
 * else this is a plain extern.
 */
#if defined(_WIN32) && !defined(OAUTH2_STATIC)
#ifdef OAUTH2_EXPORTS
#define OAUTH2_EXTERN __declspec(dllexport) extern
#else
#define OAUTH2_EXTERN __declspec(dllimport) extern
#endif
#else
#define OAUTH2_EXTERN extern
#endif

/**
 * @brief Log levels, from most to least severe.
 *
 * A sink at a given level emits the messages at that level and the
 * more severe ones, so a sink at OAUTH2_LOG_WARN emits errors and
 * warnings only.
 *
 * @note Do not change the order or the values of these without
 *       checking the consequences in log.c and in the Apache and NGINX
 *       bindings: they map the levels to their names and to the
 *       native log levels by array index.
 */
typedef enum oauth2_log_level_t {
	OAUTH2_LOG_ERROR,  /**< an operation failed */
	OAUTH2_LOG_WARN,   /**< something is off but the operation went on */
	OAUTH2_LOG_NOTICE, /**< a normal but significant event */
	OAUTH2_LOG_INFO,   /**< informational */
	OAUTH2_LOG_DEBUG,  /**< debugging: function entry and exit, decisions */
	OAUTH2_LOG_TRACE1, /**< detailed tracing: intermediate values */
	OAUTH2_LOG_TRACE2  /**< very detailed tracing: payloads, wire data */
} oauth2_log_level_t;

/**
 * @name Log macros
 * The macros the library and its users log through. They are
 * printf-style, take the log context as their first argument, capture
 * the source file, line and function of the call site and expand to
 * _oauth2_log(), which by default calls oauth2_log(). A NULL log
 * context is accepted and logs nothing.
 * @{
 */

/**
 * @brief The hook the log macros expand to.
 *
 * Defined to call oauth2_log() unless a definition is already in place
 * when this header is included: a user of the library can define it
 * beforehand to route the messages elsewhere - e.g. straight into the
 * native log call of a server, with the level mapped - or to a no-op
 * to compile the logging out for speed.
 */
#ifndef _oauth2_log
#define _oauth2_log(log, level, fmt, ...)                                      \
	oauth2_log(log, __FILE__, __LINE__, __FUNCTION__, level, fmt,          \
		   ##__VA_ARGS__)
#endif

/** @brief Log a message at OAUTH2_LOG_ERROR. */
#define oauth2_error(log, fmt, ...)                                            \
	_oauth2_log(log, OAUTH2_LOG_ERROR, fmt, ##__VA_ARGS__)
/** @brief Log a message at OAUTH2_LOG_WARN. */
#define oauth2_warn(log, fmt, ...)                                             \
	_oauth2_log(log, OAUTH2_LOG_WARN, fmt, ##__VA_ARGS__)
/** @brief Log a message at OAUTH2_LOG_NOTICE. */
#define oauth2_notice(log, fmt, ...)                                           \
	_oauth2_log(log, OAUTH2_LOG_NOTICE, fmt, ##__VA_ARGS__)
/** @brief Log a message at OAUTH2_LOG_INFO. */
#define oauth2_info(log, fmt, ...)                                             \
	_oauth2_log(log, OAUTH2_LOG_INFO, fmt, ##__VA_ARGS__)
/** @brief Log a message at OAUTH2_LOG_DEBUG. */
#define oauth2_debug(log, fmt, ...)                                            \
	_oauth2_log(log, OAUTH2_LOG_DEBUG, fmt, ##__VA_ARGS__)
/** @brief Log a message at OAUTH2_LOG_TRACE1. */
#define oauth2_trace1(log, fmt, ...)                                           \
	_oauth2_log(log, OAUTH2_LOG_TRACE1, fmt, ##__VA_ARGS__)
/** @brief Log a message at OAUTH2_LOG_TRACE2. */
#define oauth2_trace2(log, fmt, ...)                                           \
	_oauth2_log(log, OAUTH2_LOG_TRACE2, fmt, ##__VA_ARGS__)
/** @} */

/**
 * @name Log context and sinks
 * @{
 */

/** @brief Opaque log context: the list of sinks messages go to. */
typedef struct oauth2_log_t oauth2_log_t;

/**
 * @brief Opaque log sink: a level, a callback that emits the messages
 *        and an opaque context for that callback.
 */
typedef struct oauth2_log_sink_t oauth2_log_sink_t;

/**
 * @brief Sink callback, invoked for each message that passes the level
 *        of the sink.
 *
 * @param sink     the sink the message is delivered to; the context it
 *                 was created with is available through
 *                 oauth2_log_sink_ctx_get()
 * @param filename the source file of the log call
 * @param line     the source line of the log call
 * @param function the function the log call was made from
 * @param level    the level of the message
 * @param msg      the formatted message, valid for the duration of the
 *                 call only
 */
typedef void (*oauth2_log_function_t)(oauth2_log_sink_t *sink,
				      const char *filename, unsigned long line,
				      const char *function,
				      oauth2_log_level_t level,
				      const char *msg);

/**
 * @brief Built-in sink printing to stderr, at level OAUTH2_LOG_INFO
 *        initially.
 *
 * Each line reads "[file:line:function:LVL] message". The built-in
 * sinks are static objects shared by every log context they are added
 * to: oauth2_log_sink_level_set() on one affects all of them, and
 * oauth2_log_free() does not free them.
 */
OAUTH2_EXTERN oauth2_log_sink_t oauth2_log_sink_stderr;
/**
 * @brief Built-in sink printing to stdout, at level OAUTH2_LOG_INFO
 *        initially; see oauth2_log_sink_stderr.
 */
OAUTH2_EXTERN oauth2_log_sink_t oauth2_log_sink_stdout;

/**
 * @brief Format a message and deliver it to the sinks of a log
 *        context.
 *
 * Normally reached through the oauth2_error() ... oauth2_trace2()
 * macros rather than called directly. The message is formatted once
 * and handed to every sink whose level is at or above @p level, in the
 * order the sinks were added.
 *
 * @param log      the log context; NULL logs nothing
 * @param filename the source file to attribute the message to
 * @param line     the source line to attribute the message to
 * @param function the function to attribute the message to
 * @param level    the level of the message
 * @param fmt      printf-style format string, followed by its
 *                 arguments; NULL logs nothing
 */
void oauth2_log(oauth2_log_t *log, const char *filename, unsigned long line,
		const char *function, oauth2_log_level_t level, const char *fmt,
		...);

/**
 * @brief Create a sink.
 *
 * @param level    the sink emits messages at this level and the more
 *                 severe ones
 * @param callback the function that emits each message
 * @param ctx      an opaque context for the callback, e.g. the server
 *                 or request record to log against, retrievable with
 *                 oauth2_log_sink_ctx_get()
 * @return the newly allocated sink; hand it to oauth2_log_init() or
 *         oauth2_log_sink_add(), after which the log context owns it
 *         and oauth2_log_free() releases it
 */
oauth2_log_sink_t *oauth2_log_sink_create(oauth2_log_level_t level,
					  oauth2_log_function_t callback,
					  void *ctx);
/** @brief Get the context a sink was created with. */
void *oauth2_log_sink_ctx_get(oauth2_log_sink_t *sink);
/** @brief Get the callback a sink was created with. */
oauth2_log_function_t oauth2_log_sink_callback_get(oauth2_log_sink_t *sink);

/**
 * @brief Add a sink to a log context.
 *
 * The log context takes ownership: oauth2_log_free() frees every sink
 * added to it, except the built-in oauth2_log_sink_stderr and
 * oauth2_log_sink_stdout.
 *
 * @param log the log context to add the sink to
 * @param add the sink to add
 */
void oauth2_log_sink_add(oauth2_log_t *log, oauth2_log_sink_t *add);

/**
 * @brief Change the level of a sink.
 *
 * Messages less severe than @p level are no longer delivered to the
 * sink. The Apache binding uses this to apply the configured LogLevel
 * of a virtual host once the configuration has been read.
 *
 * @param sink  the sink to change
 * @param level the new level of the sink
 */
void oauth2_log_sink_level_set(oauth2_log_sink_t *sink,
			       oauth2_log_level_t level);
/** @} */

/**
 * @name Log context lifecycle
 * Prefer oauth2_init() and oauth2_shutdown() (util.h), which wrap
 * these and also initialize and clean up the global state of the
 * library (OpenSSL, libcurl, the caches); use the functions below for
 * additional, short-lived contexts such as the per-request ones the
 * server bindings create.
 * @{
 */

/**
 * @brief Create a log context with a single sink.
 *
 * @param level the level to set on @p sink
 * @param sink  the initial sink, or NULL for oauth2_log_sink_stderr;
 *              its level is overwritten with @p level, also when it is
 *              one of the shared built-in sinks
 * @return the newly allocated log context, to be released with
 *         oauth2_log_free()
 */
oauth2_log_t *oauth2_log_init(oauth2_log_level_t level,
			      oauth2_log_sink_t *sink);

/**
 * @brief Free a log context and the sinks it owns.
 *
 * Frees every sink added to the context, except the built-in
 * oauth2_log_sink_stderr and oauth2_log_sink_stdout; a NULL context is
 * ignored.
 */
void oauth2_log_free(oauth2_log_t *);
/** @} */

#endif /* _OAUTH2_LOG_H_ */
