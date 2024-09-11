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

#include "oauth2/jq.h"
#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include "jq.h"

static char *oauth2_jq_exec(oauth2_log_t *log, jq_state *jq,
			    struct jv_parser *parser)
{
	char *rv = NULL;
	jv value, elem, str, msg;

	while (jv_is_valid((value = jv_parser_next(parser)))) {
		jq_start(jq, value, 0);
		while (jv_is_valid(elem = jq_next(jq))) {
			str = jv_dump_string(elem, 0);
			rv = oauth2_strdup(jv_string_value(str));
			oauth2_debug(log, "jv_dump_string: %s", rv);
			jv_free(str);
		}
		jv_free(elem);
	}

	if (jv_invalid_has_msg(jv_copy(value))) {
		msg = jv_invalid_get_msg(value);
		oauth2_error(log, "invalid: %s", jv_string_value(msg));
		jv_free(msg);
	} else {
		jv_free(value);
	}

	return rv;
}

#define OAUTH2_JQ_FILTER_EXPIRE_DEFAULT 600
#define OAUTH2_JQ_FILTER_CACHE_TTL_ENVVAR "OAUTH2_JQ_FILTER_CACHE_TTL"

static int oauth2_jq_filter_cache_ttl(oauth2_log_t *log)
{
	// const char *s_ttl = apr_table_get(r->subprocess_env,
	// OAUTH2_JQ_FILTER_CACHE_TTL_ENVVAR); return _oauth2_str_to_int(s_ttl,
	// OAUTH2_JQ_FILTER_EXPIRE_DEFAULT);
	return OAUTH2_JQ_FILTER_EXPIRE_DEFAULT;
}

bool oauth2_jq_filter(oauth2_log_t *log, oauth2_cache_t *cache,
		      const char *input, const char *filter, char **result)
{
	bool rc = false;
	jq_state *jq = NULL;
	struct jv_parser *parser = NULL;
	int ttl = 0;
	char *key = NULL, *skey = NULL;
	char *value = NULL;

	if (filter == NULL) {
		oauth2_debug(log, "filter is NULL, abort");
		goto end;
	}

	if (input == NULL) {
		oauth2_debug(log, "input is NULL, set to empty object");
		input = "{}";
	}

	oauth2_debug(log, "processing input: %s", input);
	oauth2_debug(log, "processing filter: %s", filter);

	ttl = oauth2_jq_filter_cache_ttl(log);
	if ((cache != NULL) && (ttl > 0)) {
		skey = oauth2_stradd(NULL, (char *)input, filter, NULL);
		if (oauth2_jose_hash2s(log, OAUTH2_JOSE_OPENSSL_ALG_SHA256,
				       skey, &key) == false) {
			oauth2_error(log,
				     "oauth2_jose_hash2s returned an error");
			goto end;
		}
		oauth2_cache_get(log, cache, key, &value);
		if (value != NULL) {
			oauth2_debug(log, "return cached result: %s", value);
			*result = value;
			rc = true;
			goto end;
		}
	}

	jq = jq_init();
	if (jq == NULL) {
		oauth2_error(log, "jq_init returned NULL");
		goto end;
	}

	if (jq_compile(jq, filter) == 0) {
		oauth2_error(log, "jq_compile returned an error");
		goto end;
	}

	parser = jv_parser_new(0);
	if (parser == NULL) {
		oauth2_error(log, "jv_parser_new returned NULL");
		goto end;
	}

	jv_parser_set_buf(parser, input, strlen(input), 0);

	*result = oauth2_jq_exec(log, jq, parser);

	if ((cache != NULL) && (*result != NULL) && (ttl != 0)) {
		oauth2_debug(log, "caching result: %s", *result);
		oauth2_cache_set(log, cache, key, *result, ttl);
	}

	rc = true;

end:

	if (key)
		oauth2_mem_free(key);
	if (skey)
		oauth2_mem_free(skey);
	if (parser)
		jv_parser_free(parser);
	if (jq)
		jq_teardown(&jq);

	return rc;
}
