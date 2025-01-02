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

#include "cache_int.h"
#include "cfg_int.h"
#include "openidc_int.h"

static bool
_oauth2_openidc_provider_metadata_parse(oauth2_log_t *log, const char *s_json,
					oauth2_openidc_provider_t **provider)
{
	bool rc = false;
	json_t *json = NULL;
	oauth2_openidc_provider_t *p = NULL;

	oauth2_debug(log, "enter");

	if (oauth2_json_decode_object(log, s_json, &json) == false) {
		oauth2_error(log, "could not parse json object");
		goto end;
	}

	*provider = oauth2_openidc_provider_init(log);
	p = *provider;
	if (p == NULL)
		goto end;

	if ((oauth2_json_string_get(log, json, "issuer", &p->issuer, NULL) ==
	     false) ||
	    (p->issuer == NULL)) {
		oauth2_error(log, "could not parse issuer");
		goto end;
	}
	if (oauth2_json_string_get(log, json, "authorization_endpoint",
				   &p->authorization_endpoint, NULL) == false) {
		oauth2_error(log, "could not parse authorization_endpoint");
		goto end;
	}
	if (oauth2_json_string_get(log, json, "token_endpoint",
				   &p->token_endpoint, NULL) == false) {
		oauth2_error(log, "could not parse token_endpoint");
		goto end;
	}
	if (oauth2_json_string_get(log, json, "userinfo_endpoint",
				   &p->userinfo_endpoint, NULL) == false) {
		oauth2_error(log, "could not parse userinfo_endpoint");
		goto end;
	}
	if (oauth2_json_string_get(log, json, "jwks_uri", &p->jwks_uri, NULL) ==
	    false) {
		oauth2_error(log, "could not parse jwks_uri");
		goto end;
	}

	rc = true;

end:

	if ((rc == false) && (*provider)) {
		oauth2_openidc_provider_free(log, *provider);
		*provider = NULL;
	}
	if (json)
		json_decref(json);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

#define OAUTH_OPENIDC_PROVIDER_CACHE_EXPIRY_DEFAULT 60 * 60 * 24

bool _oauth2_openidc_provider_resolve(oauth2_log_t *log,
				      const oauth2_cfg_openidc_t *cfg,
				      const oauth2_http_request_t *request,
				      const char *issuer,
				      oauth2_openidc_provider_t **provider)
{
	bool rc = false;
	char *s_json = NULL;

	if ((cfg->provider_resolver == NULL) ||
	    (cfg->provider_resolver->callback == NULL)) {
		oauth2_error(
		    log,
		    "configuration error: provider_resolver is not configured");
		goto end;
	}

	if ((issuer) && (cfg->provider_resolver->cache)) {

		oauth2_cache_get(log, cfg->provider_resolver->cache, issuer,
				 &s_json);
	}

	if (s_json == NULL) {

		if (cfg->provider_resolver->callback(log, cfg, request,
						     &s_json) == false) {
			oauth2_error(log, "resolver callback returned false");
			goto end;
		}

		if (s_json == NULL) {
			oauth2_error(
			    log, "no provider was returned by the provider "
				 "resolver; probably a configuration error");
			goto end;
		}
	}

	if (_oauth2_openidc_provider_metadata_parse(log, s_json, provider) ==
	    false)
		goto end;

	// TODO: cache expiry configuration option
	if (cfg->provider_resolver->cache) {
		oauth2_cache_set(
		    log, cfg->provider_resolver->cache,
		    oauth2_openidc_provider_issuer_get(log, *provider), s_json,
		    OAUTH_OPENIDC_PROVIDER_CACHE_EXPIRY_DEFAULT);
	}

	rc = true;

end:

	if (s_json)
		oauth2_mem_free(s_json);

	return rc;
}

_OAUTH2_CFG_CTX_TYPE_SINGLE_STRING(oauth2_openidc_provider_resolver_file_ctx,
				   filename)

#define OAUTH2_OPENIDC_PROVIDER_RESOLVE_FILENAME_DEFAULT "conf/provider.json"

static bool _oauth2_openidc_provider_resolve_file(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, char **s_json)
{
	bool rc = false;
	oauth2_openidc_provider_resolver_file_ctx_t *ctx = NULL;
	char *filename = NULL;

	oauth2_debug(log, "enter");

	ctx = (oauth2_openidc_provider_resolver_file_ctx_t *)
		  cfg->provider_resolver->ctx->ptr;
	filename = ctx->filename
		       ? ctx->filename
		       : OAUTH2_OPENIDC_PROVIDER_RESOLVE_FILENAME_DEFAULT;

	*s_json = oauth_read_file(log, filename);
	if (*s_json == NULL)
		goto end;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

// TODO: must explicitly (re-)populate cache on startup!
#define OAUTH2_CFG_OPENIDC_PROVIDER_CACHE_DEFAULT 60 * 60 * 24

static char *_oauth2_cfg_openidc_provider_resolver_file_set_options(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    void *c)
{
	oauth2_cfg_openidc_t *cfg = (oauth2_cfg_openidc_t *)c;

	// TODO: macroize?
	cfg->provider_resolver = oauth2_cfg_openidc_provider_resolver_init(log);
	cfg->provider_resolver->callback =
	    _oauth2_openidc_provider_resolve_file;
	cfg->provider_resolver->ctx->callbacks =
	    &oauth2_openidc_provider_resolver_file_ctx_funcs;
	cfg->provider_resolver->ctx->ptr =
	    cfg->provider_resolver->ctx->callbacks->init(log);

	// TODO: factor out?
	oauth2_openidc_provider_resolver_file_ctx_t *ctx =
	    (oauth2_openidc_provider_resolver_file_ctx_t *)
		cfg->provider_resolver->ctx->ptr;
	ctx->filename = oauth2_strdup(value);

	cfg->provider_resolver->cache =
	    oauth2_cache_obtain(log, oauth2_nv_list_get(log, params, "cache"));

	return NULL;
}

_OAUTH2_CFG_CTX_TYPE_START(oauth2_openidc_provider_resolver_url_ctx)
oauth2_cfg_endpoint_t *endpoint;
_OAUTH2_CFG_CTX_TYPE_END(oauth2_openidc_provider_resolver_url_ctx)

_OAUTH2_CFG_CTX_INIT_START(oauth2_openidc_provider_resolver_url_ctx)
ctx->endpoint = NULL;
_OAUTH2_CFG_CTX_INIT_END

_OAUTH2_CFG_CTX_CLONE_START(oauth2_openidc_provider_resolver_url_ctx)
dst->endpoint = oauth2_cfg_endpoint_clone(log, src->endpoint);
_OAUTH2_CFG_CTX_CLONE_END

_OAUTH2_CFG_CTX_FREE_START(oauth2_openidc_provider_resolver_url_ctx)
if (ctx->endpoint)
	oauth2_cfg_endpoint_free(log, ctx->endpoint);
_OAUTH2_CFG_CTX_FREE_END

_OAUTH2_CFG_CTX_FUNCS(oauth2_openidc_provider_resolver_url_ctx)

static bool _oauth2_openidc_provider_resolve_url_exec(
    oauth2_log_t *log, oauth2_openidc_provider_resolver_url_ctx_t *ctx,
    char **s_json)
{
	bool rc = false;
	oauth2_http_call_ctx_t *http_ctx = NULL;
	char *s_response = NULL;
	oauth2_uint_t status_code = 0;

	oauth2_debug(log, "enter");

	http_ctx = oauth2_http_call_ctx_init(log);
	if (http_ctx == NULL)
		goto end;

	if (oauth2_http_call_ctx_ssl_verify_set(
		log, http_ctx,
		oauth2_cfg_endpoint_get_ssl_verify(ctx->endpoint)) == false)
		goto end;

	if (oauth2_http_call_ctx_timeout_set(
		log, http_ctx,
		oauth2_cfg_endpoint_get_http_timeout(ctx->endpoint)) == false)
		goto end;
	oauth2_http_call_ctx_outgoing_proxy_set(
	    log, http_ctx,
	    oauth2_cfg_endpoint_get_outgoing_proxy(ctx->endpoint));

	if (oauth2_http_get(log, oauth2_cfg_endpoint_get_url(ctx->endpoint),
			    NULL, http_ctx, s_json, &status_code) == false)
		goto end;

	if ((status_code < 200) || (status_code >= 300)) {
		goto end;
	}

	rc = true;

end:

	if (s_response)
		oauth2_mem_free(s_response);
	if (http_ctx)
		oauth2_http_call_ctx_free(log, http_ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _oauth2_openidc_provider_resolve_url(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, char **s_json)
{
	bool rc = false;
	oauth2_openidc_provider_resolver_url_ctx_t *ctx = NULL;

	oauth2_debug(log, "enter");

	ctx = (oauth2_openidc_provider_resolver_url_ctx_t *)
		  cfg->provider_resolver->ctx->ptr;
	if (ctx->endpoint == NULL)
		goto end;

	if (_oauth2_openidc_provider_resolve_url_exec(log, ctx, s_json) ==
	    false)
		goto end;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static char *_oauth2_cfg_openidc_provider_resolver_url_set_options(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    void *c)
{
	oauth2_cfg_openidc_t *cfg = (oauth2_cfg_openidc_t *)c;
	char *rv = NULL;

	// TODO: macroize?
	cfg->provider_resolver = oauth2_cfg_openidc_provider_resolver_init(log);
	cfg->provider_resolver->callback = _oauth2_openidc_provider_resolve_url;
	cfg->provider_resolver->ctx->callbacks =
	    &oauth2_openidc_provider_resolver_url_ctx_funcs;
	cfg->provider_resolver->ctx->ptr =
	    cfg->provider_resolver->ctx->callbacks->init(log);

	// TODO: factor out?
	oauth2_openidc_provider_resolver_url_ctx_t *ctx =
	    (oauth2_openidc_provider_resolver_url_ctx_t *)
		cfg->provider_resolver->ctx->ptr;

	ctx->endpoint = oauth2_cfg_endpoint_init(log);
	rv = oauth2_cfg_set_endpoint(log, ctx->endpoint, value, params, NULL);
	if (rv)
		goto end;

	cfg->provider_resolver->cache =
	    oauth2_cache_obtain(log, oauth2_nv_list_get(log, params, "cache"));

end:

	return rv;
}

// DIR

static char *_oauth2_cfg_openidc_provider_resolver_dir_set_options(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    void *c)
{

	// oauth2_cfg_cache_set_options(
	//   log, resolver->cache, "resolver",
	//  params, OAUTH2_CFG_OPENIDC_PROVIDER_CACHE_DEFAULT);

	return NULL;
}

// STRING

_OAUTH2_CFG_CTX_TYPE_SINGLE_STRING(oauth2_openidc_provider_resolver_str_ctx,
				   metadata)

static bool _oauth2_openidc_provider_resolve_string(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, char **s_json)
{
	bool rc = false;
	oauth2_openidc_provider_resolver_str_ctx_t *ctx = NULL;

	oauth2_debug(log, "enter");

	ctx = (oauth2_openidc_provider_resolver_str_ctx_t *)
		  cfg->provider_resolver->ctx->ptr;
	if (ctx->metadata == NULL) {
		oauth2_error(log, "metadata not configured");
		goto end;
	}

	*s_json = oauth2_strdup(ctx->metadata);

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static char *_oauth2_cfg_openidc_provider_resolver_string_set_options(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    void *c)
{
	oauth2_cfg_openidc_t *cfg = (oauth2_cfg_openidc_t *)c;
	oauth2_openidc_provider_resolver_str_ctx_t *ctx = NULL;

	cfg->provider_resolver = oauth2_cfg_openidc_provider_resolver_init(log);
	cfg->provider_resolver->callback =
	    _oauth2_openidc_provider_resolve_string;
	cfg->provider_resolver->ctx->callbacks =
	    &oauth2_openidc_provider_resolver_str_ctx_funcs;
	cfg->provider_resolver->ctx->ptr =
	    cfg->provider_resolver->ctx->callbacks->init(log);

	ctx = (oauth2_openidc_provider_resolver_str_ctx_t *)
		  cfg->provider_resolver->ctx->ptr;
	ctx->metadata = oauth2_strdup(value);

	return NULL;
}

#define OAUTH2_OPENIDC_PROVIDER_RESOLVER_STR_STR "string"
#define OAUTH2_OPENIDC_PROVIDER_RESOLVER_FILE_STR "file"
#define OAUTH2_OPENIDC_PROVIDER_RESOLVER_DIR_STR "dir"
#define OAUTH2_OPENIDC_PROVIDER_RESOLVER_URL_STR "url"

// clang-format off
static oauth2_cfg_set_options_ctx_t _oauth2_cfg_resolver_options_set[] = {
	{ OAUTH2_OPENIDC_PROVIDER_RESOLVER_STR_STR, _oauth2_cfg_openidc_provider_resolver_string_set_options },
	{ OAUTH2_OPENIDC_PROVIDER_RESOLVER_FILE_STR, _oauth2_cfg_openidc_provider_resolver_file_set_options },
	{ OAUTH2_OPENIDC_PROVIDER_RESOLVER_DIR_STR, _oauth2_cfg_openidc_provider_resolver_dir_set_options },
	{ OAUTH2_OPENIDC_PROVIDER_RESOLVER_URL_STR, _oauth2_cfg_openidc_provider_resolver_url_set_options },
	{ NULL, NULL }
};
// clang-format on

char *oauth2_cfg_openidc_provider_resolver_set_options(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg, const char *type,
    const char *value, const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;

	oauth2_debug(log, "type=%s value=%s options=%s", type, value, options);

	if (cfg->provider_resolver) {
		oauth2_cfg_openidc_provider_resolver_free(
		    log, cfg->provider_resolver);
		cfg->provider_resolver = NULL;
	}

	oauth2_parse_form_encoded_params(log, options, &params);
	cfg->session = _oauth2_cfg_session_obtain(
	    log, oauth2_nv_list_get(log, params, "session"));
	if (cfg->session == NULL) {
		rv = oauth2_strdup("could not configure session");
		goto end;
	}

	rv = oauth2_cfg_set_options(log, cfg, type, value, options,
				    _oauth2_cfg_resolver_options_set);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}
