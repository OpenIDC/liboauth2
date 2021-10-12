/***************************************************************************
 *
 * Copyright (C) 2018-2021 - ZmartZone Holding BV - www.zmartzone.eu
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

#include "oauth2/proto.h"
#include "oauth2/mem.h"

#include "cfg_int.h"
#include "util_int.h"

#include <ctype.h>

#define OAUTH2_CFG_SOURCE_TOKEN_HEADER_NAME_DEFAULT                            \
	OAUTH2_HTTP_HDR_AUTHORIZATION
#define OAUTH2_CFG_SOURCE_TOKEN_HEADER_TYPE_DEFAULT OAUTH2_HTTP_HDR_BEARER

static char *
_oauth2_get_source_token_from_header(oauth2_log_t *log,
				     oauth2_cfg_source_token_t *cfg,
				     oauth2_http_request_t *request)
{
	char *source_token = NULL;
	char *scheme = NULL;
	const char *auth_line = NULL;
	char *name = NULL;
	char *type = NULL;

	oauth2_debug(log, "enter");

	name = cfg->accept_in.header.name
		   ? cfg->accept_in.header.name
		   : OAUTH2_CFG_SOURCE_TOKEN_HEADER_NAME_DEFAULT;
	type = cfg->accept_in.header.type
		   ? cfg->accept_in.header.type
		   : OAUTH2_CFG_SOURCE_TOKEN_HEADER_TYPE_DEFAULT;

	auth_line = oauth2_http_request_header_get(log, request, name);
	if (auth_line == NULL)
		goto end;

	oauth2_debug(log, "%s header found", name);

	if ((type != NULL) && (strcmp(type, "") != 0)) {
		scheme = oauth2_getword(&auth_line, ' ');
		if (strcasecmp(scheme, type) != 0) {
			oauth2_warn(
			    log,
			    "client used unsupported authentication scheme: %s",
			    scheme);
			goto end;
		}
	}

	while (isspace(*auth_line))
		auth_line++;
	source_token = oauth2_strdup(auth_line);

	if (source_token != NULL)
		if (oauth2_cfg_source_token_get_strip(cfg) != 0)
			oauth2_http_request_header_unset(log, request, name);

end:

	if (scheme)
		oauth2_mem_free(scheme);

	oauth2_debug(log, "leave: %s", source_token);

	return source_token;
}

#define OAUTH2_CFG_SOURCE_TOKEN_QUERY_PARAMNAME_DEFAULT "access_token"

static char *_oauth2_get_source_token_from_query(oauth2_log_t *log,
						 oauth2_cfg_source_token_t *cfg,
						 oauth2_http_request_t *request)
{
	char *source_token = NULL;
	char *name = NULL;

	oauth2_debug(log, "enter");

	name = cfg->accept_in.query.param_name
		   ? cfg->accept_in.query.param_name
		   : OAUTH2_CFG_SOURCE_TOKEN_QUERY_PARAMNAME_DEFAULT;

	source_token = oauth2_strdup(
	    oauth2_http_request_query_param_get(log, request, name));

	if (source_token == NULL) {
		oauth2_debug(
		    log, "no source token found in query parameter: %s", name);
	} else if (oauth2_cfg_source_token_get_strip(cfg) != 0) {
		oauth2_debug(log,
			     "stripping query param %s from outgoing request",
			     name);
		oauth2_http_request_query_param_unset(log, request, name);
	}

	return source_token;
}

#define OAUTH2_CFG_SOURCE_TOKEN_POST_PARAMNAME_DEFAULT "access_token"

static char *_oauth2_get_source_token_from_post(
    oauth2_log_t *log, oauth2_cfg_source_token_t *cfg,
    oauth2_http_request_t *request, oauth2_cfg_server_callback_funcs_t *srv_cb,
    void *srv_cb_ctx)
{
	char *source_token = NULL;
	oauth2_nv_list_t *params = NULL;
	const char *content_type = NULL;
	char *name = NULL;

	oauth2_debug(log, "enter");

	name = cfg->accept_in.post.param_name
		   ? cfg->accept_in.post.param_name
		   : OAUTH2_CFG_SOURCE_TOKEN_POST_PARAMNAME_DEFAULT;

	content_type =
	    oauth2_http_request_header_content_type_get(log, request);
	if ((oauth2_http_request_method_get(log, request) !=
	     OAUTH2_HTTP_METHOD_POST) ||
	    (strcasecmp(content_type, OAUTH2_CONTENT_TYPE_FORM_ENCODED) != 0)) {
		oauth2_debug(log, "no form-encoded HTTP POST");
		goto end;
	}

	if (srv_cb->form_post(log, srv_cb_ctx, &params) == false) {
		oauth2_error(log, "HTTP POST read callback failed");
		goto end;
	}

	source_token = oauth2_strdup(oauth2_nv_list_get(log, params, name));

	if (source_token == NULL) {
		oauth2_debug(log, "no source token found in POST parameter: %s",
			     name);
	} else if (oauth2_cfg_source_token_get_strip(cfg) != 0) {
		// TBD: would work if we can remove stuff across
		// brigades/buckets in the
		// input filter...
		// sts_userdata_set_post_param(r, post_param_name,
		// NULL);
		oauth2_warn(log,
			    "stripping post param %s from outgoing request "
			    "is not supported!",
			    name);
	}

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", source_token);

	return source_token;
}

#define OAUTH2_CFG_SOURCE_TOKEN_COOKIE_NAME_DEFAULT "access_token"

static char *
_oauth2_get_source_token_from_cookie(oauth2_log_t *log,
				     oauth2_cfg_source_token_t *cfg,
				     oauth2_http_request_t *request)
{
	char *source_token = NULL;
	char *name = NULL;

	oauth2_debug(log, "enter");

	name = cfg->accept_in.cookie.name
		   ? cfg->accept_in.cookie.name
		   : OAUTH2_CFG_SOURCE_TOKEN_COOKIE_NAME_DEFAULT;

	source_token = oauth2_http_request_cookie_get(
	    log, request, name, oauth2_cfg_source_token_get_strip(cfg));
	if (source_token == NULL)
		oauth2_debug(log, "no source token found in cookie: %s", name);

	return source_token;
}

#define OAUTH2_CFG_SOURCE_TOKEN_ENVVAR_NAME_DEFAULT "access_token"

static char *_oauth2_get_source_token_from_envvar(
    oauth2_log_t *log, oauth2_cfg_source_token_t *cfg,
    oauth2_cfg_server_callback_funcs_t *srv_cb, void *srv_cb_ctx)
{
	char *source_token = NULL;
	char *name = NULL;

	oauth2_debug(log, "enter");

	name = cfg->accept_in.envvar.name
		   ? cfg->accept_in.envvar.name
		   : OAUTH2_CFG_SOURCE_TOKEN_ENVVAR_NAME_DEFAULT;

	if (srv_cb->get(log, srv_cb_ctx, name, &source_token) == false) {
		oauth2_error(log, "environment variable get callback failed");
		goto end;
	}

	if (source_token == NULL) {
		oauth2_debug(log,
			     "no source token found in %s environment variable",
			     name);
		goto end;
	};

	if (oauth2_cfg_source_token_get_strip(cfg))
		srv_cb->set(log, srv_cb_ctx, name, NULL);

end:

	return source_token;
}

static char *_oauth2_get_source_token_from_basic(oauth2_log_t *log,
						 oauth2_cfg_source_token_t *cfg,
						 oauth2_http_request_t *request)
{
	char *source_token = NULL;
	char *decoded_line = NULL;
	size_t decoded_len = 0;
	const char *auth_line = NULL;
	char *ptr = NULL;
	char *scheme = NULL;

	oauth2_debug(log, "enter");

	auth_line = oauth2_http_request_header_get(
	    log, request, OAUTH2_HTTP_HDR_AUTHORIZATION);
	if (auth_line == NULL)
		goto end;

	oauth2_debug(log, "%s header found", OAUTH2_HTTP_HDR_AUTHORIZATION);
	scheme = oauth2_getword(&auth_line, ' ');
	if ((scheme == NULL) || (strcasecmp(scheme, "Basic") != 0)) {
		oauth2_warn(log,
			    "client used unsupported "
			    "authentication scheme: %s",
			    scheme);
		goto end;
	}
	while (isspace(*auth_line))
		auth_line++;

	if (oauth2_base64_decode(log, auth_line, (uint8_t **)&decoded_line,
				 &decoded_len) == false)
		goto end;
	decoded_line[decoded_len] = '\0';

	ptr = decoded_line;
	if (strchr(ptr, ':') != NULL) {
		oauth2_mem_free(oauth2_getword((const char **)&ptr, ':'));
		source_token = oauth2_strdup(ptr);
	}

	if ((source_token != NULL) &&
	    (oauth2_cfg_source_token_get_strip(cfg) != 0))
		oauth2_http_request_header_unset(log, request,
						 OAUTH2_HTTP_HDR_AUTHORIZATION);

end:

	if (scheme)
		oauth2_mem_free(scheme);
	if (decoded_line)
		oauth2_mem_free(decoded_line);

	return source_token;
}

char *oauth2_get_source_token(oauth2_log_t *log, oauth2_cfg_source_token_t *cfg,
			      oauth2_http_request_t *request,
			      oauth2_cfg_server_callback_funcs_t *srv_cb,
			      void *srv_cb_ctx)
{

	char *source_token = NULL;

	char accept_source_token_in =
	    oauth2_cfg_source_token_get_accept_in(cfg);

	if ((source_token == NULL) &&
	    (accept_source_token_in & OAUTH2_CFG_TOKEN_IN_ENVVAR))
		source_token = _oauth2_get_source_token_from_envvar(
		    log, cfg, srv_cb, srv_cb_ctx);

	if ((source_token == NULL) &&
	    (accept_source_token_in & OAUTH2_CFG_TOKEN_IN_HEADER))
		source_token =
		    _oauth2_get_source_token_from_header(log, cfg, request);

	if ((source_token == NULL) &&
	    (accept_source_token_in & OAUTH2_CFG_TOKEN_IN_QUERY)) {
		source_token =
		    _oauth2_get_source_token_from_query(log, cfg, request);
	}

	if ((source_token == NULL) &&
	    (accept_source_token_in & OAUTH2_CFG_TOKEN_IN_POST)) {
		source_token = _oauth2_get_source_token_from_post(
		    log, cfg, request, srv_cb, srv_cb_ctx);
	}

	if ((source_token == NULL) &&
	    (accept_source_token_in & OAUTH2_CFG_TOKEN_IN_COOKIE))
		source_token =
		    _oauth2_get_source_token_from_cookie(log, cfg, request);

	if ((source_token == NULL) &&
	    (accept_source_token_in & OAUTH2_CFG_TOKEN_IN_BASIC))
		source_token =
		    _oauth2_get_source_token_from_basic(log, cfg, request);

	if (source_token == NULL) {
		oauth2_debug(log,
			     "no source token found in any of the configured "
			     "methods: %x",
			     accept_source_token_in);
	}

	return source_token;
}

bool oauth2_proto_request(oauth2_log_t *log,
			  const oauth2_cfg_endpoint_t *token_endpoint,
			  oauth2_http_call_ctx_t *ctx,
			  const oauth2_nv_list_t *params, char **rtoken,
			  oauth2_uint_t *status_code)
{
	bool rc = false;
	char *response = NULL;
	json_t *result = NULL;
	char *tkn = NULL;

	oauth2_http_call_ctx_ssl_verify_set(
	    log, ctx, oauth2_cfg_endpoint_get_ssl_verify(token_endpoint));
	oauth2_http_call_ctx_timeout_set(
	    log, ctx, oauth2_cfg_endpoint_get_http_timeout(token_endpoint));
	// oauth2_http_call_ctx_outgoing_proxy_set(log, ctx, outgoing_proxy);

	if (oauth2_http_post_form(log,
				  oauth2_cfg_endpoint_get_url(token_endpoint),
				  params, ctx, &response, status_code) == false)
		goto end;

	if ((*status_code < 200) || (*status_code >= 300))
		goto end;

	if (oauth2_json_decode_check_error(log, response, &result) == false)
		goto end;

	if (oauth2_json_string_get(log, result, OAUTH2_ACCESS_TOKEN, &tkn,
				   NULL) == false)
		goto end;

	if (tkn == NULL) {
		oauth2_error(log, "no access token found in result");
		goto end;
	}

	*rtoken = oauth2_strdup(tkn);

	rc = true;

	/*
	 char **token_type = NULL;
	 sts_util_json_object_get_string(r->pool, result, "token_type",
	 token_type,
	 NULL);

	 if (token_type != NULL) {
	 if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE)
	 {
	 oidc_warn(r, "access token type did not validate, dropping it");
	 *access_token = NULL;
	 }
	 }

	 sts_util_json_object_get_int(r->pool, result, OIDC_PROTO_EXPIRES_IN,
	 expires_in,
	 -1);

	 sts_util_json_object_get_string(r->pool, result,
	 OIDC_PROTO_REFRESH_TOKEN,
	 refresh_token,
	 NULL);
	 */

end:

	if (response)
		oauth2_mem_free(response);
	if (tkn)
		oauth2_mem_free(tkn);
	if (result)
		json_decref(result);

	return rc;
}

#define OAUTH2_PROTO_ROPC_GRANT_TYPE_VALUE "password"
#define OAUTH2_PROTO_ROPC_USERNAME "username"
#define OAUTH2_PROTO_ROPC_PASSWORD "password"

bool oauth2_ropc_exec(oauth2_log_t *log, oauth2_cfg_ropc_t *cfg,
		      const char *username, const char *password, char **rtoken,
		      oauth2_uint_t *status_code)
{

	bool rc = false;
	oauth2_nv_list_t *params = NULL;
	oauth2_http_call_ctx_t *ctx = NULL;
	const char *client_id = oauth2_cfg_ropc_get_client_id(cfg);
	const oauth2_cfg_endpoint_t *token_endpoint =
	    oauth2_cfg_ropc_get_token_endpoint(cfg);

	oauth2_debug(log, "enter");

	if (cfg == NULL) {
		oauth2_error(log, "token endpoint cfg is not set");
		goto end;
	}
	if (token_endpoint == NULL) {
		oauth2_warn(log, "token endpoint is not set");
		goto end;
	}
	params = oauth2_nv_list_init(log);
	oauth2_nv_list_add(log, params, OAUTH2_GRANT_TYPE,
			   OAUTH2_PROTO_ROPC_GRANT_TYPE_VALUE);

	if ((oauth2_cfg_endpoint_auth_type(oauth2_cfg_endpoint_get_auth(
		 token_endpoint)) == OAUTH2_ENDPOINT_AUTH_NONE) &&
	    (client_id != NULL))
		oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID, client_id);

	if (username != NULL)
		oauth2_nv_list_add(log, params, OAUTH2_PROTO_ROPC_USERNAME,
				   username);
	oauth2_nv_list_add(log, params, OAUTH2_PROTO_ROPC_PASSWORD, password);

	oauth2_nv_list_merge_into(
	    log, oauth2_cfg_ropc_get_request_parameters(cfg), params);

	ctx = oauth2_http_call_ctx_init(log);
	if (ctx == NULL)
		goto end;

	oauth2_http_call_ctx_ssl_verify_set(
	    log, ctx, oauth2_cfg_endpoint_get_ssl_verify(token_endpoint));
	oauth2_http_call_ctx_outgoing_proxy_set(
	    log, ctx, oauth2_cfg_endpoint_get_outgoing_proxy(token_endpoint));

	if (oauth2_http_ctx_auth_add(
		log, ctx, oauth2_cfg_endpoint_get_auth(token_endpoint),
		params) == false)
		goto end;

	rc = oauth2_proto_request(log, oauth2_cfg_ropc_get_token_endpoint(cfg),
				  ctx, params, rtoken, status_code);

end:

	if (params)
		oauth2_nv_list_free(log, params);
	if (ctx)
		oauth2_http_call_ctx_free(log, ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}
