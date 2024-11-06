#ifndef _OAUTH2_LOG_H_
#define _OAUTH2_LOG_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
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

// don't change this without checking consequences in log.c...
typedef enum oauth2_log_level_t {
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_WARN,
	OAUTH2_LOG_NOTICE,
	OAUTH2_LOG_INFO,
	OAUTH2_LOG_DEBUG,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE2
} oauth2_log_level_t;

// TODO: instead of sinks, just define oauth2_err_t and use that to return
// errors...?

// we must use #define to make the __ macro's work...
// we must use the target defined log levels...
// so #define all of oauth2_error, oauth2_warn, oauth2_debug, oauth2_trace1?
// must also keep oauth2_error etc. to printout logs in the test phase (although
// could do that with oauth2_err_t)
// probably good to print debug traces inside protocol functions!

//         #define _oauth2_log
//         ap_log_rerror(APLOG_MARK, level, 0, r,"%s: %s", __FUNCTION__,
//         apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
//       and:
//         #define_oauth2_log
//         ap_log_error(APLOG_MARK, level, 0, s, "%s: %s", __FUNCTION__,
//         apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))

// can also #define _oauth2_log to a no-op for speed or other reasons
#ifndef _oauth2_log
#define _oauth2_log(log, level, fmt, ...)                                      \
	oauth2_log(log, __FILE__, __LINE__, __FUNCTION__, level, fmt,          \
		   ##__VA_ARGS__)
#endif

#define oauth2_error(log, fmt, ...)                                            \
	_oauth2_log(log, OAUTH2_LOG_ERROR, fmt, ##__VA_ARGS__)
#define oauth2_warn(log, fmt, ...)                                             \
	_oauth2_log(log, OAUTH2_LOG_WARN, fmt, ##__VA_ARGS__)
#define oauth2_notice(log, fmt, ...)                                           \
	_oauth2_log(log, OAUTH2_LOG_NOTICE, fmt, ##__VA_ARGS__)
#define oauth2_info(log, fmt, ...)                                             \
	_oauth2_log(log, OAUTH2_LOG_INFO, fmt, ##__VA_ARGS__)
#define oauth2_debug(log, fmt, ...)                                            \
	_oauth2_log(log, OAUTH2_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define oauth2_trace1(log, fmt, ...)                                           \
	_oauth2_log(log, OAUTH2_LOG_TRACE1, fmt, ##__VA_ARGS__)
#define oauth2_trace2(log, fmt, ...)                                           \
	_oauth2_log(log, OAUTH2_LOG_TRACE2, fmt, ##__VA_ARGS__)

/*
 * log context definitions
 */

typedef struct oauth2_log_t oauth2_log_t;

/*
 * log sink types
 */

typedef struct oauth2_log_sink_t oauth2_log_sink_t;

typedef void (*oauth2_log_function_t)(oauth2_log_sink_t *sink,
				      const char *filename, unsigned long line,
				      const char *function,
				      oauth2_log_level_t level,
				      const char *msg);

/*
 * API
 */

extern oauth2_log_sink_t oauth2_log_sink_stderr;
extern oauth2_log_sink_t oauth2_log_sink_stdout;

void oauth2_log(oauth2_log_t *log, const char *filename, unsigned long line,
		const char *function, oauth2_log_level_t level, const char *fmt,
		...);

oauth2_log_sink_t *oauth2_log_sink_create(oauth2_log_level_t level,
					  oauth2_log_function_t callback,
					  void *ctx);
void *oauth2_log_sink_ctx_get(oauth2_log_sink_t *sink);
oauth2_log_function_t oauth2_log_sink_callback_get(oauth2_log_sink_t *sink);
void oauth2_log_sink_add(oauth2_log_t *log, oauth2_log_sink_t *add);
void oauth2_log_sink_level_set(oauth2_log_sink_t *sink,
			       oauth2_log_level_t level);

/*
 * internals
 */
oauth2_log_t *oauth2_log_init(oauth2_log_level_t level,
			      oauth2_log_sink_t *sink);
void oauth2_log_free(oauth2_log_t *);

#endif /* _OAUTH2_LOG_H_ */
