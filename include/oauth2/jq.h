#ifndef _OAUTH2_JQ_H
#define _OAUTH2_JQ_H

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
 * @file jq.h
 * @brief Claim filtering and transformation with jq expressions.
 *
 * Runs a jq filter (https://jqlang.github.io/jq/) over a JSON
 * document, typically the claims of a verified token, to select,
 * reshape or rename them before they are passed on to the target
 * application. Only available when the library was built against
 * libjq (configure --with-jq): this header is installed and its
 * functions implemented only then, and the library's pkg-config
 * cflags define OAUTH2_WITH_JQ so that consumers can test for it.
 */

#include "oauth2/cache.h"
#include "oauth2/log.h"

/** @brief Opaque libjq program state, declared here to avoid jq.h. */
typedef struct jq_state jq_state;

/**
 * @brief Compile a jq filter expression.
 *
 * Useful to validate a filter at configuration time.
 *
 * @param log    the log handle to use
 * @param filter the jq filter expression to compile
 * @param r_jq   when non-NULL, set to the compiled program, to be
 *               released by the caller with jq_teardown(); when NULL
 *               the program is compiled for validation only and
 *               released internally
 * @return true when the filter compiled, false on error
 */
bool oauth2_jq_filter_compile(oauth2_log_t *log, const char *filter,
			      jq_state **r_jq);

/**
 * @brief Apply a jq filter to a JSON document.
 *
 * Parses @p input, runs the compiled @p filter over it and returns
 * the last value the filter produced, serialized as compact JSON.
 * When a cache is passed, the result is looked up in and stored to
 * it under a SHA-256 hash of the input and filter, with a fixed
 * time-to-live of 600 seconds.
 *
 * @param log    the log handle to use
 * @param cache  the cache to memoize results in, or NULL to run the
 *               filter every time
 * @param input  the JSON document to filter; NULL is treated as an
 *               empty object
 * @param filter the jq filter expression
 * @param result on success, set to the filter output as a newly
 *               allocated string, to be released with
 *               oauth2_mem_free(), or to NULL when the filter produced
 *               no output (e.g. "empty" or a parse error in the
 *               input)
 * @return true when the filter was applied (or served from the
 *         cache), false when @p filter is NULL, does not compile or
 *         the cache key could not be computed
 */
bool oauth2_jq_filter(oauth2_log_t *log, oauth2_cache_t *cache,
		      const char *input, const char *filter, char **result);

#endif /* _OAUTH2_JQ_H */
