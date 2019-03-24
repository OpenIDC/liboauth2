/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include <oauth2/apache.h>
#include <oauth2/http.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>

#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_strings.h>

// clang-format off
oauth2_uint_t log_level_apache2oauth2[] = {
    OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_WARN,
	OAUTH2_LOG_NOTICE,
	OAUTH2_LOG_INFO,
	OAUTH2_LOG_DEBUG,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE2,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE1,
	OAUTH2_LOG_TRACE1
};

oauth2_uint_t log_level_log2apache[] = {
	APLOG_ERR,
	APLOG_WARNING,
	APLOG_NOTICE,
	APLOG_INFO,
	APLOG_DEBUG,
	APLOG_TRACE1,
	APLOG_TRACE1
};

oauth2_http_method_t request_method_apache2oauth2[] = {
	OAUTH2_HTTP_METHOD_GET,
	OAUTH2_HTTP_METHOD_PUT,
	OAUTH2_HTTP_METHOD_POST,
	OAUTH2_HTTP_METHOD_DELETE,
	OAUTH2_HTTP_METHOD_CONNECT,
	OAUTH2_HTTP_METHOD_OPTIONS,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_UNKNOWN
};
// clang-format on

static apr_status_t oauth2_apache_cfg_srv_free(void *data)
{
	oauth2_apache_cfg_srv_t *cfg = (oauth2_apache_cfg_srv_t *)data;
	if (cfg) {
		if (cfg->log)
			oauth2_log_free(cfg->log);
		oauth2_mem_free(cfg);
	}

	return APR_SUCCESS;
}

void *oauth2_apache_cfg_srv_create(apr_pool_t *pool, server_rec *s,
				   oauth2_log_function_t server_log_cb)
{
	oauth2_apache_cfg_srv_t *cfg =
	    (oauth2_apache_cfg_srv_t *)oauth2_mem_alloc(
		sizeof(oauth2_apache_cfg_srv_t));

	cfg->sink = oauth2_mem_alloc(sizeof(oauth2_log_sink_t));
	cfg->sink->callback = server_log_cb;
	// NB: this is not actually set to the/a configured level here...
	cfg->sink->level = (s && (s->log.level != -1))
			       ? log_level_apache2oauth2[s->log.level]
			       : OAUTH2_LOG_TRACE1;
	cfg->sink->ctx = s;
	cfg->log = oauth2_log_init(cfg->sink->level, cfg->sink);

	return cfg;
}

void *oauth2_apache_cfg_srv_merge(apr_pool_t *pool, void *b, void *a)
{
	oauth2_apache_cfg_srv_t *add = (oauth2_apache_cfg_srv_t *)a;
	oauth2_apache_cfg_srv_t *cfg = oauth2_apache_cfg_srv_create(
	    pool, (server_rec *)add->sink->ctx, add->sink->callback);
	return cfg;
}

/*
 * parent/child cleanup
 */

apr_status_t oauth2_apache_child_cleanup(void *data, module *m,
					 const char *package_name_version)
{
	oauth2_apache_cfg_srv_t *cfg = NULL;
	server_rec *sp = NULL;
	for (sp = (server_rec *)data; sp; sp = sp->next) {
		cfg = (oauth2_apache_cfg_srv_t *)ap_get_module_config(
		    sp->module_config, m);
		oauth2_apache_cfg_srv_free(cfg);
	}
	oauth2_shutdown(NULL);
	return APR_SUCCESS;
}

apr_status_t oauth2_apache_parent_cleanup(void *data, module *m,
					  const char *package_name_version)
{
	server_rec *s = (server_rec *)data;
	oauth2_apache_cfg_srv_t *cfg =
	    (oauth2_apache_cfg_srv_t *)ap_get_module_config(s->module_config,
							    m);
	oauth2_info(cfg->log, "%s-%s - shutdown", package_name_version,
		    oauth2_package_string());
	oauth2_apache_child_cleanup(cfg, m, package_name_version);
	return APR_SUCCESS;
}

/*
 * post config
 */

int oauth2_apache_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2,
			      server_rec *s, module *m,
			      const char *package_name_version,
			      apache_cleanup_handler_t parent_cleanup,
			      apache_cleanup_handler_t child_cleanup)
{
	void *data = NULL;
	oauth2_log_t *p = NULL;
	oauth2_apache_cfg_srv_t *cfg = NULL;
	server_rec *sp = NULL;

	apr_pool_userdata_get(&data, package_name_version, s->process->pool);

	if (data == NULL) {
		apr_pool_userdata_set((const void *)1, package_name_version,
				      apr_pool_cleanup_null, s->process->pool);
		goto end;
	}

	p = oauth2_init(OAUTH2_LOG_INFO, NULL);
	oauth2_log_free(p);

	sp = s;
	for (sp = s; sp; sp = sp->next) {
		cfg = (oauth2_apache_cfg_srv_t *)ap_get_module_config(
		    sp->module_config, m);
		// only now the level has been set according to the config!
		cfg->sink->level = (sp && (sp->log.level != -1))
				       ? log_level_apache2oauth2[sp->log.level]
				       : OAUTH2_LOG_TRACE1;
	}

	apr_pool_cleanup_register(pool, s, parent_cleanup, child_cleanup);

	cfg = (oauth2_apache_cfg_srv_t *)ap_get_module_config(s->module_config,
							      m);
	oauth2_info(cfg->log, "%s-%s - init", package_name_version,
		    oauth2_package_string());

end:

	return OK;
}

static int oauth2_apache_http_request_hdr_add(void *rec, const char *key,
					      const char *value)
{
	oauth2_apache_request_ctx_t *ctx = (oauth2_apache_request_ctx_t *)rec;
	return (oauth2_http_request_hdr_in_set(ctx->log, ctx->request, key,
					       value) == true);
}

static oauth2_apache_request_ctx_t *
oauth2_apache_request_context_init(request_rec *r,
				   oauth2_log_function_t request_log_cb)
{
	oauth2_apache_request_ctx_t *ctx = NULL;
	oauth2_log_sink_t *log_sink_apache = NULL;

	// TODO: memory allocation failure checks...?
	ctx = oauth2_mem_alloc(sizeof(oauth2_apache_request_ctx_t));

	ctx->r = r;

	// TODO: more elegant log-for-request handling
	log_sink_apache = oauth2_mem_alloc(sizeof(oauth2_log_sink_t));
	log_sink_apache->callback = request_log_cb;
	log_sink_apache->level = (r && r->log)
				     ? log_level_apache2oauth2[r->log->level]
				     : OAUTH2_LOG_TRACE1;
	log_sink_apache->level = OAUTH2_LOG_TRACE1;
	log_sink_apache->ctx = r;
	ctx->log = oauth2_log_init(log_sink_apache->level, log_sink_apache);

	ctx->request = oauth2_http_request_init(ctx->log);

	oauth2_http_request_scheme_set(ctx->log, ctx->request,
#ifdef APACHE2_0
				       (char *)ap_http_method(r)
#else
				       (char *)ap_http_scheme(r)
#endif
	);

	oauth2_http_request_hostname_set(ctx->log, ctx->request,
					 ap_get_server_name(r));
	oauth2_http_request_port_set(ctx->log, ctx->request,
				     r->connection->local_addr->port);
	oauth2_http_request_path_set(ctx->log, ctx->request, r->uri);
	oauth2_http_request_method_set(
	    ctx->log, ctx->request,
	    request_method_apache2oauth2[r->method_number]);
	oauth2_http_request_query_set(ctx->log, ctx->request, r->args);

	apr_table_do(oauth2_apache_http_request_hdr_add, ctx, r->headers_in,
		     NULL);

	oauth2_debug(ctx->log, "created request context: %p", ctx);

	return ctx;
}

static apr_status_t oauth2_apache_request_context_free(void *rec)
{
	oauth2_apache_request_ctx_t *ctx = (oauth2_apache_request_ctx_t *)rec;
	if (ctx) {
		oauth2_debug(ctx->log, "dispose request context: %p", ctx);
		oauth2_http_request_free(ctx->log, ctx->request);
		oauth2_log_free(ctx->log);
		oauth2_mem_free(ctx);
	}
	return APR_SUCCESS;
}

oauth2_apache_request_ctx_t *
oauth2_apache_request_context(request_rec *r,
			      oauth2_log_function_t request_log_cb,
			      const char *user_data_key)
{
	oauth2_apache_request_ctx_t *ctx = NULL;
	apr_pool_userdata_get((void **)&ctx, user_data_key, r->pool);
	if (ctx == NULL) {
		ctx = oauth2_apache_request_context_init(r, request_log_cb);
		apr_pool_userdata_set((const void *)ctx, user_data_key,
				      oauth2_apache_request_context_free,
				      r->pool);
	}
	return ctx;
}

int oauth2_apache_return_www_authenticate(oauth2_cfg_source_token_t *cfg,
					  oauth2_apache_request_ctx_t *ctx,
					  int status_code, const char *error,
					  const char *error_description)
{
	oauth2_uint_t accept_token_in = OAUTH2_CFG_UINT_UNSET;
	char *hdr = NULL;

	oauth2_debug(ctx->log, "enter");

	accept_token_in = oauth2_cfg_source_token_get_accept_in(cfg);

	if (accept_token_in == OAUTH2_CFG_TOKEN_IN_BASIC) {
		hdr = apr_psprintf(ctx->r->pool, "%s", OAUTH2_HTTP_HDR_BASIC);
	} else {
		hdr = apr_psprintf(ctx->r->pool, "%s", OAUTH2_HTTP_HDR_BEARER);
	}

	if (ap_auth_name(ctx->r) != NULL)
		hdr = apr_psprintf(ctx->r->pool, "%s %s=\"%s\"", hdr,
				   OAUTH2_HTTP_HDR_REALM, ap_auth_name(ctx->r));
	if (error != NULL)
		hdr = apr_psprintf(ctx->r->pool, "%s%s %s=\"%s\"", hdr,
				   (ap_auth_name(ctx->r) ? "," : ""),
				   OAUTH2_ERROR, error);
	if (error_description != NULL)
		hdr = apr_psprintf(ctx->r->pool, "%s, %s=\"%s\"", hdr,
				   OAUTH2_ERROR_DESCRIPTION, error_description);

	oauth2_apache_hdr_out_add(ctx->log, ctx->r,
				  OAUTH2_HTTP_HDR_WWW_AUTHENTICATE, hdr);

	oauth2_debug(ctx->log, "leave");

	return status_code;
}

bool oauth2_apache_request_header_set(oauth2_log_t *log, void *rec,
				      const char *name, const char *value)
{
	request_rec *r = (request_rec *)rec;
	oauth2_debug(log, "setting request header: %s=%s", name, value);
	apr_table_set(r->headers_in, name, value);
	return true;
}

bool oauth2_apache_http_request_set(oauth2_log_t *log,
				    oauth2_http_request_t *request,
				    request_rec *r)
{
	bool rc = false;

	if (request == NULL)
		goto end;

	oauth2_http_request_hdr_in_loop(log, request,
					oauth2_apache_request_header_set, r);

	r->args =
	    apr_pstrdup(r->pool, oauth2_http_request_query_get(log, request));

	rc = true;

end:

	return rc;
}

void oauth2_apache_hdr_out_add(oauth2_log_t *log, const request_rec *r,
			       const char *name, const char *value)
{
	oauth2_debug(log, "%s: %s", name, value);
	apr_table_add(r->err_headers_out, name, value);
}

void oauth2_apache_scrub_headers(oauth2_apache_request_ctx_t *ctx,
				 oauth2_cfg_target_pass_t *target_pass)
{

	apr_hash_t *scrub_hdrs = NULL;
	const char *prefix = NULL;
	int prefix_len = 0;
	const char *authn_hdr = NULL;
	const apr_array_header_t *h = NULL;
	const apr_table_entry_t *e = NULL;
	const char *k = NULL;
	apr_table_t *clean_headers = NULL;
	bool prefix_matches = false;
	bool header_matches = false;
	int i = 0;
	const char *hdr = NULL;

	if (oauth2_cfg_target_pass_get_as_headers(target_pass) == false)
		goto end;

	prefix = oauth2_cfg_target_pass_get_prefix(target_pass);
	scrub_hdrs = apr_hash_make(ctx->r->pool);

	if (strcmp(prefix, "") == 0) {
		/*
		if ((cfg->white_listed_claims != NULL)
				&& (apr_hash_count(cfg->white_listed_claims) >
		0)) scrub_hdrs = apr_hash_overlay(r->pool,
		cfg->white_listed_claims, scrub_hdrs); else oidc_warn(r, "both "
		OIDCClaimPrefix " and " OIDCWhiteListedClaims " are empty: this
		renders an insecure setup!");
		*/
	}

	authn_hdr = oauth2_cfg_target_pass_get_authn_header(target_pass);
	if (authn_hdr != NULL)
		apr_hash_set(scrub_hdrs, authn_hdr, APR_HASH_KEY_STRING,
			     authn_hdr);

	prefix_len = prefix ? strlen(prefix) : 0;

	h = apr_table_elts(ctx->r->headers_in);
	clean_headers = apr_table_make(ctx->r->pool, h->nelts);
	e = (const apr_table_entry_t *)h->elts;
	for (i = 0; i < h->nelts; i++) {
		k = e[i].key;
		hdr = (k != NULL) && (scrub_hdrs != NULL)
			  ? apr_hash_get(scrub_hdrs, k, APR_HASH_KEY_STRING)
			  : NULL;
		header_matches =
		    (hdr != NULL) && (oauth2_strnenvcmp(k, hdr, -1) == 0);
		prefix_matches =
		    (k != NULL) && prefix_len &&
		    (oauth2_strnenvcmp(k, prefix, prefix_len) == 0);
		if (prefix_matches || header_matches) {
			oauth2_warn(
			    ctx->log,
			    "cleaned suspicious request header (%s: %.32s)", k,
			    e[i].val);
			continue;
		}
		apr_table_addn(clean_headers, k, e[i].val);
	}

	ctx->r->headers_in = clean_headers;

end:

	return;
}

static const char *oauth2_apache_get_envvar(oauth2_log_t *log, request_rec *r,
					    const char *name)
{
	oauth2_debug(log, "get environment variable: %s", name);
	return apr_table_get(r->subprocess_env, name);
}

static void oauth2_apache_set_envvar(oauth2_log_t *log, request_rec *r,
				     const char *name, const char *value)
{
	oauth2_debug(log, "set environment variable: %s=%s", name, value);
	if (value)
		apr_table_set(r->subprocess_env, name, value);
	else
		apr_table_unset(r->subprocess_env, name);

	/*
	#define OAUTH2_APACHE2_USERDATA_ENV_KEY
	"oauth2_apache_userdata_env_key"
	 *
	// TODO: pull and set in fixup handler
	apr_table_t *env = NULL;
	apr_pool_userdata_get((void **) &env, OAUTH2_APACHE2_USERDATA_ENV_KEY,
	r->pool); if (env == NULL) env = apr_table_make(r->pool, 5);
	apr_table_set(env, name, value);
	apr_pool_userdata_set(env, OAUTH2_APACHE2_USERDATA_ENV_KEY, NULL,
	r->pool);
	 */
}

#define OAUTH2_MAX_POST_DATA_LEN 1024 * 1024

static bool oauth2_apache_post_read(oauth2_log_t *log, request_rec *r,
				    char **rbuf)
{
	bool rc = false;
	apr_size_t bytes_read;
	apr_size_t bytes_left;
	apr_size_t len;
	long read_length;

	if (ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK) != OK)
		goto end;

	len = ap_should_client_block(r) ? r->remaining : 0;

	if (len > OAUTH2_MAX_POST_DATA_LEN) {
		oauth2_error(
		    log,
		    "POST parameter value is too large: %lu bytes (max=%d)",
		    (unsigned long)len, OAUTH2_MAX_POST_DATA_LEN);
		goto end;
	}

	*rbuf = oauth2_mem_alloc(len + 1);
	if (*rbuf == NULL) {
		oauth2_error(
		    log,
		    "could not allocate memory for %lu bytes of POST data.",
		    (unsigned long)len);
		goto end;
	}
	(*rbuf)[len] = '\0';

	bytes_read = 0;
	bytes_left = len;
	while (bytes_left > 0) {
		read_length =
		    ap_get_client_block(r, &(*rbuf)[bytes_read], bytes_left);
		if (read_length == 0) {
			(*rbuf)[bytes_read] = '\0';
			break;
		} else if (read_length < 0) {
			oauth2_error(log,
				     "failed to read POST data from client");
			goto end;
		}
		bytes_read += read_length;
		bytes_left -= read_length;
	}

	rc = true;

end:

	if ((rc == false) && (*rbuf)) {
		oauth2_mem_free(*rbuf);
		*rbuf = NULL;
	}

	return rc;
}

static void oauth2_apache_set_target_info(oauth2_apache_request_ctx_t *ctx,
					  oauth2_cfg_target_pass_t *target_pass,
					  const char *key, const char *value)
{

	char *norm = NULL, *name = NULL;

	norm = oauth2_normalize_header_name(key);
	if (norm == NULL)
		goto end;

	name = oauth2_stradd(
	    NULL, oauth2_cfg_target_pass_get_prefix(target_pass), norm, NULL);
	if (name == NULL)
		goto end;

	if (oauth2_cfg_target_pass_get_as_headers(target_pass))
		oauth2_apache_request_header_set(ctx->log, ctx->r, name, value);

	if (oauth2_cfg_target_pass_get_as_envvars(target_pass))
		oauth2_apache_set_envvar(ctx->log, ctx->r, name, value);

end:

	if (norm)
		oauth2_mem_free(norm);
	if (name)
		oauth2_mem_free(name);
}

static void
oauth2_apache_set_target_infos(oauth2_apache_request_ctx_t *ctx,
			       oauth2_cfg_target_pass_t *target_pass,
			       json_t *json_token)
{
	void *iter = NULL;
	const char *key = NULL;
	json_t *value = NULL;
	char *v = NULL;
	iter = json_object_iter(json_token);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if (json_is_string(value)) {
			v = oauth2_strdup(json_string_value(value));
		} else {
			v = oauth2_json_encode(ctx->log, value,
					       JSON_ENCODE_ANY);
		}
		oauth2_apache_set_target_info(ctx, target_pass, key, v);
		if (v)
			oauth2_mem_free(v);
		iter = json_object_iter_next(json_token, iter);
	}
}

void oauth2_apache_target_pass(oauth2_apache_request_ctx_t *ctx,
			       oauth2_cfg_target_pass_t *target_pass,
			       const char *target_token, json_t *json_token)
{
	const char *authn_hdr = NULL;

	authn_hdr = oauth2_cfg_target_pass_get_authn_header(target_pass);

	if ((ctx->r->user != NULL) && (authn_hdr != NULL))
		oauth2_apache_request_header_set(ctx->log, ctx->r, authn_hdr,
						 ctx->r->user);

	oauth2_apache_set_target_infos(ctx, target_pass, json_token);

	if (target_token != NULL) {
		// TODO: hmmm, "access_token" or "target_token" or "token" or
		// configurable...?
		oauth2_apache_set_target_info(ctx, target_pass, "access_token",
					      target_token);
	}

	// TODO: strip cookies according to config setting
	// oauth2_http:strip_cookies(r);
}

bool oauth2_apache_set_request_user(oauth2_cfg_target_pass_t *target_pass,
				    oauth2_apache_request_ctx_t *ctx,
				    json_t *json_token)
{
	bool rc = false;
	const char *claim = NULL;
	json_t *remote_user = NULL;

	if ((target_pass == NULL) || (json_token == NULL))
		goto end;

	claim = oauth2_cfg_target_get_remote_user_claim(target_pass);
	if (claim == NULL) {
		oauth2_error(ctx->log, "remote user claim was not set");
		goto end;
	}

	remote_user = json_object_get(json_token, claim);
	if ((remote_user == NULL) || (!json_is_string(remote_user))) {
		oauth2_error(ctx->log, "remote user claim could not be found");
		goto end;
	}

	ctx->r->user =
	    apr_pstrdup(ctx->r->pool, json_string_value(remote_user));

	oauth2_debug(ctx->log, "set user to \"%s\" based on claim: %s=%s",
		     ctx->r->user, claim, remote_user);

	// TODO: more flexibility and or regular expressions?

	rc = true;

end:

	return rc;
}

static bool _oauth2_apache_env_get_cb(oauth2_log_t *log, void *ctx,
				      const char *name, char **value)
{
	*value = oauth2_strdup(
	    oauth2_apache_get_envvar(log, (request_rec *)ctx, name));
	return true;
}

static bool _oauth2_apache_env_set_cb(oauth2_log_t *log, void *ctx,
				      const char *name, const char *value)
{
	oauth2_apache_set_envvar(log, (request_rec *)ctx, name, value);
	return true;
}

static bool _oauth2_apache_read_form_post(oauth2_log_t *log, void *ctx,
					  oauth2_nv_list_t **params)
{
	bool rc = false;
	char *data = NULL;

	if (oauth2_apache_post_read(log, (request_rec *)ctx, &data) == false)
		goto end;

	if (oauth2_parse_form_encoded_params(log, data, params) == false)
		goto end;

	rc = true;

end:

	if (data)
		oauth2_mem_free(data);

	return rc;
}

// clang-format off
oauth2_cfg_server_callback_funcs_t oauth2_apache_server_callback_funcs = {
    _oauth2_apache_env_get_cb,
	_oauth2_apache_env_set_cb,
    _oauth2_apache_read_form_post
};
// clang-format on
