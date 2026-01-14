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

#include <oauth2/mem.h>

#include "cfg_int.h"
#include "openidc_int.h"
#include "util_int.h"

oauth2_openidc_client_t *oauth2_openidc_client_init(oauth2_log_t *log)
{
	oauth2_openidc_client_t *c = NULL;

	c = oauth2_mem_alloc(sizeof(oauth2_openidc_client_t));
	if (c == NULL)
		goto end;

	c->client_id = NULL;
	c->client_secret = NULL;
	c->scope = NULL;
	c->authn_request_params = NULL;
	c->token_endpoint_auth = NULL;
	c->ssl_verify = OAUTH2_CFG_FLAG_UNSET;
	c->http_timeout = OAUTH2_CFG_UINT_UNSET;
	c->http_retries = OAUTH2_CFG_UINT_UNSET;
	c->http_retry_interval = OAUTH2_CFG_UINT_UNSET;

end:

	return c;
}

void oauth2_openidc_client_free(oauth2_log_t *log, oauth2_openidc_client_t *c)
{
	if (c == NULL)
		goto end;

	if (c->client_id)
		oauth2_mem_free(c->client_id);
	if (c->client_secret)
		oauth2_mem_free(c->client_secret);
	if (c->scope)
		oauth2_mem_free(c->scope);
	if (c->authn_request_params)
		oauth2_mem_free(c->authn_request_params);
	if (c->token_endpoint_auth)
		oauth2_cfg_endpoint_auth_free(log, c->token_endpoint_auth);

	oauth2_mem_free(c);

end:

	return;
}

oauth2_openidc_client_t *
oauth2_openidc_client_clone(oauth2_log_t *log,
			    const oauth2_openidc_client_t *src)
{
	oauth2_openidc_client_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_openidc_client_init(log);
	if (dst == NULL)
		goto end;

	dst->client_id = oauth2_strdup(src->client_id);
	dst->client_secret = oauth2_strdup(src->client_secret);
	dst->scope = oauth2_strdup(src->scope);
	dst->authn_request_params = oauth2_strdup(src->authn_request_params);
	dst->token_endpoint_auth =
	    oauth2_cfg_endpoint_auth_clone(log, src->token_endpoint_auth);
	dst->ssl_verify = src->ssl_verify;
	dst->http_timeout = src->http_timeout;
	dst->http_retries = src->http_retries;
	dst->http_retry_interval = src->http_retry_interval;

end:

	return dst;
}

static char *_oauth2_openidc_client_metadata_parse(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg, const char *s_json,
    const oauth2_nv_list_t *options_params)
{
	char *rv = NULL;
	json_t *json = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	char *value = NULL;
	oauth2_nv_list_t *params = NULL;

	oauth2_debug(log, "enter");

	if ((cfg == NULL) || (cfg->client == NULL) || (s_json == NULL)) {
		rv = oauth2_strdup(
		    "internal error: struct, client or json is NULL");
		goto end;
	}

	if (oauth2_json_decode_object(log, s_json, &json) == false) {
		rv = oauth2_strdup("could not parse json object");
		goto end;
	}

	params = options_params ? oauth2_nv_list_clone(log, options_params)
				: oauth2_nv_list_init(log);

	if ((oauth2_json_string_get(log, json, "client_id", &value, NULL) ==
	     false) ||
	    (value == NULL)) {
		rv = oauth2_strdup("could not parse client_id");
		goto end;
	}
	if (value) {
		// TODO: better merging?
		oauth2_nv_list_add(log, params, "client_id", value);
		oauth2_openidc_client_client_id_set(log, cfg->client, value);
		oauth2_mem_free(value);
		value = NULL;
	}

	if (oauth2_json_string_get(log, json, "client_secret", &value, NULL) ==
	    false) {
		rv = oauth2_strdup("could not parse client_secret");
		goto end;
	}
	if (value) {
		// TODO: better merging?
		oauth2_nv_list_add(log, params, "client_secret", value);
		oauth2_openidc_client_client_secret_set(log, cfg->client,
							value);
		oauth2_mem_free(value);
		value = NULL;
	}

	if (oauth2_json_string_get(log, json, "scope", &value, NULL) == false) {
		rv = oauth2_strdup("could not parse scope");
		goto end;
	}
	if (value) {
		oauth2_openidc_client_scope_set(log, cfg->client, value);
		oauth2_mem_free(value);
		value = NULL;
	}

	if (oauth2_json_string_get(log, json, "authn_request_params", &value,
				   NULL) == false) {
		rv = oauth2_strdup("could not parse authn_request_params");
		goto end;
	}
	if (value) {
		oauth2_openidc_client_authn_request_params_set(log, cfg->client,
							       value);
		oauth2_mem_free(value);
		value = NULL;
	}

	auth = oauth2_cfg_endpoint_auth_init(log);

	value = NULL;
	if (oauth2_json_string_get(log, json, "token_endpoint_auth_method",
				   &value, NULL) == false) {
		rv =
		    oauth2_strdup("could not parse token_endpoint_auth_method");
		oauth2_cfg_endpoint_auth_free(log, auth);
		goto end;
	}

	if (value == NULL) {
		oauth2_cfg_endpoint_auth_free(log, auth);
		goto end;
	}

	rv = oauth2_cfg_set_endpoint_auth(log, auth, value, params, NULL);
	if (rv != NULL) {
		oauth2_cfg_endpoint_auth_free(log, auth);
		goto end;
	}

	oauth2_cfg_endpoint_auth_free(
	    log,
	    oauth2_openidc_client_token_endpoint_auth_get(log, cfg->client));
	oauth2_openidc_client_token_endpoint_auth_set(log, cfg->client, auth);

end:

	if ((rv != NULL) && (cfg->client)) {
		oauth2_openidc_client_free(log, cfg->client);
		cfg->client = NULL;
	}

	if (value)
		oauth2_mem_free(value);
	if (params)
		oauth2_nv_list_free(log, params);
	if (json)
		json_decref(json);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

static char *
_oauth2_openidc_client_set_options_file(oauth2_log_t *log, const char *filename,
					const oauth2_nv_list_t *params, void *c)
{
	oauth2_cfg_openidc_t *cfg = (oauth2_cfg_openidc_t *)c;
	char *s_json = NULL;
	char *rv = NULL;

	s_json = oauth_read_file(log, filename);
	if (s_json == NULL)
		goto end;

	rv = _oauth2_openidc_client_metadata_parse(log, cfg, s_json, params);

end:

	if (s_json)
		oauth2_mem_free(s_json);

	return rv;
}

static char *
_oauth2_openidc_client_set_options_json(oauth2_log_t *log, const char *value,
					const oauth2_nv_list_t *params, void *c)
{
	oauth2_cfg_openidc_t *cfg = (oauth2_cfg_openidc_t *)c;
	return _oauth2_openidc_client_metadata_parse(log, cfg, value, params);
}

static char *
_oauth2_openidc_client_set_options_string(oauth2_log_t *log, const char *value,
					  const oauth2_nv_list_t *params,
					  void *c)
{
	oauth2_cfg_openidc_t *cfg = (oauth2_cfg_openidc_t *)c;
	char *rv = NULL;
	oauth2_nv_list_t *client_params = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;

	oauth2_debug(log, "enter");

	if (oauth2_parse_form_encoded_params(log, value, &client_params) ==
	    false) {
		rv = oauth2_strdup("could not parse parameters");
		goto end;
	}

	oauth2_openidc_client_client_id_set(
	    log, cfg->client,
	    oauth2_nv_list_get(log, client_params, "client_id"));
	oauth2_openidc_client_client_secret_set(
	    log, cfg->client,
	    oauth2_nv_list_get(log, client_params, "client_secret"));
	oauth2_openidc_client_scope_set(
	    log, cfg->client, oauth2_nv_list_get(log, client_params, "scope"));
	oauth2_openidc_client_authn_request_params_set(
	    log, cfg->client,
	    oauth2_nv_list_get(log, client_params, "authn_request_params"));

	auth = oauth2_cfg_endpoint_auth_init(log);

	// TODO: merge client_params and params?
	rv = oauth2_cfg_set_endpoint_auth(
	    log, auth,
	    oauth2_nv_list_get(log, client_params,
			       "token_endpoint_auth_method"),
	    client_params, NULL);

	if (rv != NULL) {
		oauth2_cfg_endpoint_auth_free(log, auth);
		goto end;
	}

	oauth2_cfg_endpoint_auth_free(
	    log,
	    oauth2_openidc_client_token_endpoint_auth_get(log, cfg->client));
	oauth2_openidc_client_token_endpoint_auth_set(log, cfg->client, auth);

end:

	if (client_params)
		oauth2_nv_list_free(log, client_params);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, scope, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, authn_request_params,
				      char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, client_id, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, client_secret, char *,
				      str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, token_endpoint_auth,
				      oauth2_cfg_endpoint_auth_t *, ptr)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, ssl_verify,
				      oauth2_flag_t, bln)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, http_timeout,
				      oauth2_uint_t, uint)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(openidc, client, http_retries, oauth2_uint_t,
				  uint)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(openidc, client, http_retry_interval,
				  oauth2_uint_t, uint)

#define OAUTH2_OPENIDC_CLIENT_HTTP_RETRIES_DEFAULT 1

oauth2_uint_t
oauth2_openidc_client_http_retries_get(oauth2_log_t *log,
				       const oauth2_openidc_client_t *client)
{
	if ((client == NULL) || (client->http_retries == OAUTH2_CFG_UINT_UNSET))
		return OAUTH2_OPENIDC_CLIENT_HTTP_RETRIES_DEFAULT;
	return client->http_retries;
}

#define OAUTH2_OPENIDC_CLIENT_HTTP_RETRY_INTERVAL_DEFAULT 300

oauth2_uint_t oauth2_openidc_client_http_retry_interval_get(
    oauth2_log_t *log, const oauth2_openidc_client_t *client)
{
	if ((client == NULL) ||
	    (client->http_retry_interval == OAUTH2_CFG_UINT_UNSET))
		return OAUTH2_OPENIDC_CLIENT_HTTP_RETRY_INTERVAL_DEFAULT;
	return client->http_retry_interval;
}

#define OAUTH2_OPENIDC_RESOLVER_STRING_STR "string"
#define OAUTH2_OPENIDC_RESOLVER_JSON_STR "json"
#define OAUTH2_OPENIDC_RESOLVER_FILE_STR "file"

// clang-format off
static oauth2_cfg_set_options_ctx_t _oauth2_cfg_client_resolver_options_set[] = {
	{ OAUTH2_OPENIDC_RESOLVER_STRING_STR, _oauth2_openidc_client_set_options_string },
	{ OAUTH2_OPENIDC_RESOLVER_JSON_STR, _oauth2_openidc_client_set_options_json },
	{ OAUTH2_OPENIDC_RESOLVER_FILE_STR, _oauth2_openidc_client_set_options_file },
	{ NULL, NULL }
};
// clang-format on

char *oauth2_openidc_client_set_options(oauth2_log_t *log,
					oauth2_cfg_openidc_t *cfg,
					const char *type, const char *value,
					const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;

	oauth2_debug(log, "type=%s value=%s options=%s", type, value, options);

	if (cfg->client == NULL) {
		cfg->client = oauth2_openidc_client_init(log);
		if (cfg->client == NULL) {
			rv = oauth2_strdup("could not create client");
			goto end;
		}
	}

	if (oauth2_parse_form_encoded_params(log, options, &params) == false) {
		rv = oauth2_strdup("could not parse parameters");
		goto end;
	}

	cfg->session = _oauth2_cfg_session_obtain(
	    log, oauth2_nv_list_get(log, params, "session"));
	if (cfg->session == NULL) {
		rv = oauth2_strdup("could not obtain session");
		goto end;
	}

	rv = oauth2_strdup(oauth2_cfg_set_flag_slot(
	    cfg->client, offsetof(oauth2_openidc_client_t, ssl_verify),
	    oauth2_nv_list_get(log, params, "ssl_verify")));
	if (rv != NULL)
		goto end;

	rv = oauth2_cfg_set_options(log, cfg, type, value, options,
				    _oauth2_cfg_client_resolver_options_set);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}
