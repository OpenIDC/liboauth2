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

#include "oauth2/log.h"
#include "oauth2/mem.h"

#include "oauth2/jose.h"
#include "oauth2/openidc.h"
#include "oauth2/session.h"

#include "cfg_int.h"
#include "jose_int.h"
#include "util_int.h"

#include <string.h>

// TODO: set add log
typedef struct oauth2_cfg_openidc_t {
	char *handler_path;
	char *redirect_uri;
	oauth2_cfg_openidc_provider_resolver_t *provider_resolver;
	oauth2_unauth_action_t unauth_action;
	char *state_cookie_name_prefix;
	char *passphrase;
} oauth2_cfg_openidc_t;

oauth2_cfg_openidc_t *oauth2_cfg_openidc_init(oauth2_log_t *log)
{
	oauth2_cfg_openidc_t *c = NULL;

	c = oauth2_mem_alloc(sizeof(oauth2_cfg_openidc_t));
	if (c == NULL)
		goto end;

	c->handler_path = NULL;
	c->redirect_uri = NULL;
	c->provider_resolver = NULL;
	c->unauth_action = OAUTH2_UNAUTH_ACTION_UNDEFINED;
	c->state_cookie_name_prefix = NULL;
	c->passphrase = NULL;

end:

	return c;
}

oauth2_cfg_openidc_t *oauth2_cfg_openidc_clone(oauth2_log_t *log,
					       oauth2_cfg_openidc_t *src)
{
	oauth2_cfg_openidc_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_openidc_init(log);
	if (dst == NULL)
		goto end;

	dst->handler_path = oauth2_strdup(src->handler_path);
	dst->redirect_uri = oauth2_strdup(src->redirect_uri);
	dst->provider_resolver = src->provider_resolver;
	dst->unauth_action = src->unauth_action;
	dst->state_cookie_name_prefix =
	    oauth2_strdup(src->state_cookie_name_prefix);
	dst->passphrase = oauth2_strdup(src->passphrase);

end:

	return dst;
}

#define _OAUTH_CFG_MERGE_STRING(cfg, base, add, x)                             \
	cfg->x = oauth2_strdup(add->x ? add->x : base->x);
#define _OAUTH_CFG_MERGE_VALUE(cfg, base, add, x, undefined)                   \
	cfg->x = add->x != undefined ? add->x : base->x;

void oauth2_cfg_openidc_merge(oauth2_log_t *log, oauth2_cfg_openidc_t *cfg,
			      oauth2_cfg_openidc_t *base,
			      oauth2_cfg_openidc_t *add)
{

	if ((cfg == NULL) || (base == NULL) || (add == NULL))
		goto end;

	_OAUTH_CFG_MERGE_STRING(cfg, base, add, handler_path);
	_OAUTH_CFG_MERGE_STRING(cfg, base, add, redirect_uri);
	_OAUTH_CFG_MERGE_VALUE(cfg, base, add, provider_resolver, NULL)
	_OAUTH_CFG_MERGE_VALUE(cfg, base, add, unauth_action,
			       OAUTH2_UNAUTH_ACTION_UNDEFINED)
	_OAUTH_CFG_MERGE_STRING(cfg, base, add, state_cookie_name_prefix);
	_OAUTH_CFG_MERGE_STRING(cfg, base, add, passphrase);

end:

	return;
}

void oauth2_cfg_openidc_free(oauth2_log_t *log, oauth2_cfg_openidc_t *c)
{
	if (c == NULL)
		goto end;

	if (c->handler_path)
		oauth2_mem_free(c->handler_path);
	if (c->redirect_uri)
		oauth2_mem_free(c->redirect_uri);
	if (c->state_cookie_name_prefix)
		oauth2_mem_free(c->state_cookie_name_prefix);
	if (c->passphrase)
		oauth2_mem_free(c->passphrase);

	oauth2_mem_free(c);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, handler_path, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, redirect_uri, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, state_cookie_name_prefix,
				  char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(cfg, openidc, passphrase, char *, str)
/*
bool oauth2_cfg_openidc_provider_resolver_set(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg,
    oauth2_openidc_provider_resolver_t *resolver)
{
	cfg->provider_resolver = resolver;
	return true;
}

oauth2_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_get(oauth2_log_t *log,
					 const oauth2_cfg_openidc_t *cfg)
{
	return cfg->provider_resolver;
}
*/
#define OAUTH2_OPENIDC_CFG_HANDLER_PATH_DEFAULT "/openid-connect"

char *oauth2_openidc_cfg_handler_path_get(oauth2_log_t *log,
					  const oauth2_cfg_openidc_t *c)
{
	return c->handler_path ? c->handler_path
			       : OAUTH2_OPENIDC_CFG_HANDLER_PATH_DEFAULT;
}

char *oauth2_cfg_openidc_redirect_uri_get(oauth2_log_t *log,
					  const oauth2_cfg_openidc_t *c,
					  const oauth2_http_request_t *r)
{
	char *redirect_uri = NULL, *path = NULL;

	if (c == NULL)
		goto end;

	if (c->redirect_uri) {
		if (c->redirect_uri[0] != _OAUTH2_CHAR_FSLASH) {
			// absolute redirect uri
			redirect_uri = oauth2_strdup(c->redirect_uri);
			goto end;
		}
		path = oauth2_strdup(c->redirect_uri);
	} else {
		path = oauth2_stradd(
		    NULL, oauth2_openidc_cfg_handler_path_get(log, c),
		    "/redirect_uri", NULL);
	}

	redirect_uri = oauth2_http_request_url_base_get(log, r);
	if (redirect_uri == NULL)
		goto end;

	redirect_uri = oauth2_stradd(redirect_uri, path, NULL, NULL);

	oauth2_debug(log, "derived absolute redirect uri: %s", redirect_uri);

end:

	if (path)
		oauth2_mem_free(path);

	return redirect_uri;
}

char *
oauth2_openidc_cfg_state_cookie_name_prefix_get(oauth2_log_t *log,
						const oauth2_cfg_openidc_t *cfg)
{
	return cfg->state_cookie_name_prefix
		   ? cfg->state_cookie_name_prefix
		   : OAUTH2_OPENIDC_STATE_COOKIE_NAME_PREFIX_DEFAULT;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(cfg, openidc, unauth_action,
				      oauth2_unauth_action_t, uint)

typedef struct oauth2_openidc_provider_t {
	char *issuer;
	char *authorization_endpoint;
	char *token_endpoint;
	oauth2_cfg_endpoint_auth_t *token_endpoint_auth;
	char *jwks_uri;
	char *scope;
	char *client_id;
	char *client_secret;
	bool ssl_verify;
} oauth2_openidc_provider_t;

oauth2_openidc_provider_t *oauth2_openidc_provider_init(oauth2_log_t *log)
{
	oauth2_openidc_provider_t *p = NULL;

	p = oauth2_mem_alloc(sizeof(oauth2_openidc_provider_t));
	if (p == NULL)
		goto end;

	p->issuer = NULL;
	p->authorization_endpoint = NULL;
	p->token_endpoint = NULL;
	p->token_endpoint_auth = NULL;
	p->jwks_uri = NULL;
	p->scope = NULL;
	p->client_id = NULL;
	p->client_secret = NULL;
	p->ssl_verify = true;

end:

	return p;
}

void oauth2_openidc_provider_free(oauth2_log_t *log,
				  oauth2_openidc_provider_t *p)
{
	if (p == NULL)
		goto end;

	if (p->issuer)
		oauth2_mem_free(p->issuer);
	if (p->authorization_endpoint)
		oauth2_mem_free(p->authorization_endpoint);
	if (p->token_endpoint)
		oauth2_mem_free(p->token_endpoint);
	if (p->token_endpoint_auth)
		oauth2_cfg_endpoint_auth_free(log, p->token_endpoint_auth);
	if (p->jwks_uri)
		oauth2_mem_free(p->jwks_uri);
	if (p->scope)
		oauth2_mem_free(p->scope);
	if (p->client_id)
		oauth2_mem_free(p->client_id);
	if (p->client_secret)
		oauth2_mem_free(p->client_secret);

	oauth2_mem_free(p);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, issuer, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, authorization_endpoint,
				      char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, token_endpoint, char *,
				      str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, token_endpoint_auth,
				      oauth2_cfg_endpoint_auth_t *, ptr)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, jwks_uri, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, scope, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, client_id, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, client_secret, char *,
				      str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, ssl_verify, bool, bln)

char *oauth2_cfg_openidc_redirect_uri_get_iss(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *c,
    const oauth2_http_request_t *r, const oauth2_openidc_provider_t *provider)
{
	char *redirect_uri = NULL, *issuer = NULL, *sep = NULL;

	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	if (redirect_uri == NULL)
		goto end;

	// if (provider->issuer_specific_redirect_uri != 0) {

	if (provider->issuer)
		issuer = oauth2_url_encode(log, provider->issuer);

	if (issuer == NULL)
		goto end;

	sep = strchr(redirect_uri, _OAUTH2_CHAR_QUERY) != NULL
		  ? _OAUTH2_STR_AMP
		  : _OAUTH2_STR_QMARK;
	redirect_uri = _oauth2_stradd4(redirect_uri, sep, "iss",
				       _OAUTH2_STR_EQUAL, issuer);

end:
	if (issuer)
		oauth2_mem_free(issuer);

	return redirect_uri;
}

// TODO: refactor into its own class/methods

#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_ISSUER "i"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_TARGET_LINK_URI "l"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_REQUEST_METHOD "m"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_MODE "r"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_TYPE "y"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_TIMESTAMP "t"

static json_t *_oauth2_openidc_proto_state_create(
    oauth2_log_t *log, oauth2_openidc_provider_t *provider,
    const char *target_link_uri, const oauth2_http_request_t *request)
{
	json_t *proto_state = json_object();

	json_object_set_new(
	    proto_state, _OAUTH2_OPENIDC_PROTO_STATE_KEY_ISSUER,
	    json_string(oauth2_openidc_provider_issuer_get(log, provider)));
	json_object_set_new(proto_state,
			    _OAUTH2_OPENIDC_PROTO_STATE_KEY_TARGET_LINK_URI,
			    json_string(target_link_uri));
	json_object_set_new(
	    proto_state, _OAUTH2_OPENIDC_PROTO_STATE_KEY_REQUEST_METHOD,
	    json_integer(oauth2_http_request_method_get(log, request)));
	// json_object_set_new(proto_state,
	// _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_MODE,
	// provider->response_mode); json_object_set_new(proto_state,
	// _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_TYPE,
	// provider->response_type);
	json_object_set_new(proto_state,
			    _OAUTH2_OPENIDC_PROTO_STATE_KEY_TIMESTAMP,
			    json_integer(oauth2_time_now_sec()));

	return proto_state;
}

static bool _oauth2_openidc_proto_state_delete(oauth2_log_t *log,
					       json_t *proto_state)
{
	if (proto_state)
		json_decref(proto_state);
	return true;
}

static bool _oauth2_openidc_set_state_cookie(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    oauth2_openidc_provider_t *provider, const oauth2_http_request_t *request,
    oauth2_http_response_t *response, const char *state)
{
	bool rc = false;
	char *name = NULL, *value = NULL, *target_link_uri = NULL;
	json_t *proto_state = NULL;

	name = oauth2_stradd(
	    name, oauth2_openidc_cfg_state_cookie_name_prefix_get(log, cfg),
	    state, NULL);
	if (name == NULL)
		goto end;

	target_link_uri = oauth2_http_request_url_get(log, request);

	// TODO: add different state policy that keeps track in the shared cache
	// of outstanding parallel requests from the same client (ip/user-agent)
	// against a configurable maximum and uses only a single shared cookie
	// across those requests (accepting consecutive responses, or take the
	// last one)

	proto_state = _oauth2_openidc_proto_state_create(
	    log, provider, target_link_uri, request);

	if (oauth2_jose_jwt_encrypt(log,
				    oauth2_cfg_openidc_passphrase_get(log, cfg),
				    proto_state, &value) == false)
		goto end;

	// TODO: get cookie path from config
	rc = oauth2_http_response_cookie_set(log, response, name, value, "/");

end:

	if (proto_state)
		_oauth2_openidc_proto_state_delete(log, proto_state);
	if (name)
		oauth2_mem_free(name);
	if (value)
		oauth2_mem_free(value);
	if (target_link_uri)
		oauth2_mem_free(target_link_uri);

	return rc;
}

static bool _oauth2_openidc_get_state_cookie(oauth2_log_t *log,
					     const oauth2_cfg_openidc_t *cfg,
					     oauth2_http_request_t *request,
					     oauth2_http_response_t *response,
					     const char *state,
					     json_t **proto_state)
{
	bool rc = false;
	char *name = NULL, *value = NULL;

	name = oauth2_stradd(
	    name, oauth2_openidc_cfg_state_cookie_name_prefix_get(log, cfg),
	    state, NULL);
	if (name == NULL)
		goto end;

	value = oauth2_http_request_cookie_get(log, request, name, true);
	if (value == NULL) {
		oauth2_warn(log, "no state cookie found");
		goto end;
	}

	// TODO: get state cookie path from config
	rc = oauth2_http_response_cookie_set(log, response, name, NULL, "/");

	if (oauth2_jose_jwt_decrypt(log,
				    oauth2_cfg_openidc_passphrase_get(log, cfg),
				    value, proto_state) == false)
		goto end;

end:

	if (name)
		oauth2_mem_free(name);
	if (value)
		oauth2_mem_free(value);

	return rc;
}

typedef bool(oauth2_openidc_provider_resolver_func_t)(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *, oauth2_openidc_provider_t **);

typedef struct oauth2_cfg_openidc_provider_resolver_t {
	oauth2_openidc_provider_resolver_func_t *callback;
	oauth2_cfg_ctx_t *ctx;
	oauth2_cfg_cache_t *cache;
} oauth2_cfg_openidc_provider_resolver_t;

oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_init(oauth2_log_t *log)
{
	oauth2_cfg_openidc_provider_resolver_t *c = NULL;

	c = oauth2_mem_alloc(sizeof(oauth2_cfg_openidc_provider_resolver_t));
	if (c == NULL)
		goto end;

	c->cache = oauth2_cfg_cache_init(log);
	;
	c->callback = NULL;
	c->ctx = oauth2_cfg_ctx_init(log);
	;

end:

	return c;
}

oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_clone(
    oauth2_log_t *log, oauth2_cfg_openidc_provider_resolver_t *src)
{
	oauth2_cfg_openidc_provider_resolver_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_openidc_provider_resolver_init(log);
	if (dst == NULL)
		goto end;

	dst->cache = oauth2_cfg_cache_clone(log, src->cache);
	dst->callback = src->callback;
	dst->ctx = oauth2_cfg_ctx_clone(log, src->ctx);

end:

	return dst;
}

void oauth2_cfg_openidc_provider_resolver_merge(
    oauth2_log_t *log, oauth2_cfg_openidc_provider_resolver_t *cfg,
    oauth2_cfg_openidc_provider_resolver_t *base,
    oauth2_cfg_openidc_provider_resolver_t *add)
{

	if ((cfg == NULL) || (base == NULL) || (add == NULL))
		goto end;

	cfg->cache = add->cache ? oauth2_cfg_cache_clone(log, add->cache)
				: oauth2_cfg_cache_clone(log, base->cache);
	cfg->callback = add->cache ? add->callback : base->callback;
	cfg->ctx = add->ctx ? oauth2_cfg_ctx_clone(log, add->ctx)
			    : oauth2_cfg_ctx_clone(log, base->ctx);

end:

	return;
}

void oauth2_cfg_openidc_provider_resolver_free(
    oauth2_log_t *log, oauth2_cfg_openidc_provider_resolver_t *c)
{
	if (c == NULL)
		goto end;

	if (c->cache)
		oauth2_cfg_cache_free(log, c->cache);
	if (c->ctx)
		oauth2_cfg_ctx_free(log, c->ctx);

	oauth2_mem_free(c);

end:

	return;
}

static bool _oauth2_openidc_provider_resolve(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, oauth2_openidc_provider_t **provider)
{
	bool rc = false;

	if ((cfg->provider_resolver == NULL) ||
	    (cfg->provider_resolver->callback == NULL)) {
		oauth2_error(
		    log,
		    "configuration error: provider_resolver is not configured");
		goto end;
	}

	if (cfg->provider_resolver->callback(log, cfg, request, provider) ==
	    false) {
		oauth2_error(log, "resolver callback returned false");
		goto end;
	}

	if (provider == NULL) {
		oauth2_error(log, "no provider was returned by the provider "
				  "resolver; probably a configuration error");
		goto end;
	}

	rc = true;

end:

	return rc;
}

static bool _oauth2_openidc_authenticate(oauth2_log_t *log,
					 const oauth2_cfg_openidc_t *cfg,
					 const oauth2_http_request_t *request,
					 oauth2_http_response_t **response)
{
	bool rc = false;
	oauth2_openidc_provider_t *provider = NULL;
	char *nonce = NULL, *state = NULL, *redirect_uri = NULL,
	     *location = NULL;
	oauth2_nv_list_t *params = oauth2_nv_list_init(log);

	oauth2_debug(log, "enter");

	if ((cfg == NULL) || (request == NULL) || (response == NULL))
		goto end;

	if (_oauth2_openidc_provider_resolve(log, cfg, request, &provider) ==
	    false)
		goto end;

	oauth2_nv_list_add(log, params, OAUTH2_RESPONSE_TYPE,
			   OAUTH2_RESPONSE_TYPE_CODE);

	if (provider->client_id)
		oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID,
				   provider->client_id);

	// redirect_uri = oauth2_openidc_cfg_redirect_uri_get_iss(log, cfg,
	// request, provider);
	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, cfg, request);
	if (redirect_uri)
		oauth2_nv_list_add(log, params, OAUTH2_REDIRECT_URI,
				   redirect_uri);

	if (provider->scope)
		oauth2_nv_list_add(log, params, OAUTH2_SCOPE, provider->scope);

	nonce = oauth2_rand_str(log, 10);
	oauth2_nv_list_add(log, params, OAUTH2_NONCE, nonce);

	state = oauth2_rand_str(log, 10);
	oauth2_nv_list_add(log, params, OAUTH2_STATE, state);

	// TODO: handle POST binding as well

	*response = oauth2_http_response_init(log);
	if (*response == NULL)
		goto end;

	if (_oauth2_openidc_set_state_cookie(log, cfg, provider, request,
					     *response, state) == false)
		goto end;

	location = oauth2_http_url_query_encode(
	    log, provider->authorization_endpoint, params);

	if (oauth2_http_response_header_set(
		log, *response, OAUTH2_HTTP_HDR_LOCATION, location) == false)
		goto end;

	rc = oauth2_http_response_status_code_set(log, *response, 302);

end:

	if (redirect_uri)
		oauth2_mem_free(redirect_uri);
	if (nonce)
		oauth2_mem_free(nonce);
	if (state)
		oauth2_mem_free(state);
	if (location)
		oauth2_mem_free(location);
	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

static bool _oauth2_openidc_unauthenticated_request(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, oauth2_session_rec_t *session,
    oauth2_http_response_t **response)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	if (response == NULL)
		goto end;
	*response = oauth2_http_response_init(log);

	switch (oauth2_cfg_openidc_unauth_action_get(log, cfg)) {
	case OAUTH2_UNAUTH_ACTION_PASS:
		// r->user = "";
		// oidc_scrub_headers(r);
		goto end;
		break;
	case OAUTH2_UNAUTH_ACTION_HTTP_401:
		oauth2_http_response_status_code_set(log, *response, 401);
		rc = true;
		goto end;
		break;
	case OAUTH2_UNAUTH_ACTION_HTTP_410:
		oauth2_http_response_status_code_set(log, *response, 410);
		rc = true;
		goto end;
		break;
	case OAUTH2_UNAUTH_ACTION_AUTHENTICATE:
	case OAUTH2_UNAUTH_ACTION_UNDEFINED:
	default:
		if (oauth2_http_request_is_xml_http_request(log, request)) {
			oauth2_http_response_status_code_set(log, *response,
							     410);
			rc = true;
			goto end;
		}
		break;
	}

	rc = _oauth2_openidc_authenticate(log, cfg, request, response);

end:

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

static bool _oauth2_openidc_existing_session(oauth2_log_t *log,
					     const oauth2_cfg_openidc_t *c,
					     const oauth2_http_request_t *r,
					     oauth2_session_rec_t *session,
					     oauth2_http_response_t **response,
					     json_t **claims)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	goto end;

end:

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

static bool _oauth2_openidc_redirect_uri_handler(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    oauth2_http_request_t *request, oauth2_session_rec_t *session,
    oauth2_http_response_t **response, json_t **claims)
{
	bool rc = false;
	oauth2_openidc_provider_t *provider = NULL;
	const char *code = NULL, *state = NULL;
	oauth2_http_call_ctx_t *http_ctx = NULL;
	oauth2_uint_t status_code = 0;
	oauth2_nv_list_t *params = NULL;
	char *redirect_uri = NULL, *s_response = NULL, *location = NULL,
	     *s_id_token = NULL, *options = NULL; //, *s_payload = NULL;
	json_t *json = NULL, *proto_state = NULL, *id_token = NULL;
	char *rv = NULL;

	oauth2_debug(log, "enter");

	// at this point we know there's a request to the redirect uri
	// errors set in the HTTP response

	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, cfg, request);

	code = oauth2_http_request_query_param_get(log, request, OAUTH2_CODE);
	state = oauth2_http_request_query_param_get(log, request, OAUTH2_STATE);

	if ((code == NULL) || (state == NULL)) {
		oauth2_error(log, "invalid request to the redirect_uri: %s",
			     oauth2_http_request_query_get(log, request));
		goto end;
	}

	*response = oauth2_http_response_init(log);

	if (_oauth2_openidc_get_state_cookie(log, cfg, request, *response,
					     state, &proto_state) == false)
		goto end;

	// TODO: combine with state cookie / restore proto state in case
	// resolver = dir?
	if (_oauth2_openidc_provider_resolve(log, cfg, request, &provider) ==
	    false)
		goto end;

	http_ctx = oauth2_http_call_ctx_init(log);
	if (http_ctx == NULL)
		goto end;

	if (oauth2_http_call_ctx_ssl_verify_set(log, http_ctx,
						provider->ssl_verify) == false)
		goto end;

	params = oauth2_nv_list_init(log);
	if (params == NULL)
		goto end;

	oauth2_nv_list_add(log, params, OAUTH2_GRANT_TYPE,
			   OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
	oauth2_nv_list_add(log, params, OAUTH2_CODE, code);
	oauth2_nv_list_add(log, params, OAUTH2_REDIRECT_URI, redirect_uri);

	// TODO: add configurable extra POST params

	if (oauth2_http_ctx_auth_add(
		log, http_ctx, provider->token_endpoint_auth, params) == false)
		goto end;

	if (oauth2_http_post_form(log, provider->token_endpoint, params,
				  http_ctx, &s_response, &status_code) == false)
		goto end;

	if ((status_code < 200) || (status_code >= 300)) {
		rc = false;
		goto end;
	}

	if (oauth2_json_decode_check_error(log, s_response, &json) == false)
		goto end;

	if (oauth2_json_string_get(log, json, OAUTH2_OPENIDC_ID_TOKEN,
				   &s_id_token, NULL) == false) {
		oauth2_error(log, "no id_token found in token response");
		goto end;
	}

	// TODO: creating this on the fly creates a cache on the fly...
	//       this needs to become a configuration item
	oauth2_cfg_token_verify_t *verify = NULL;
	options = oauth2_stradd(NULL, "jwks_uri.ssl_verify", "=",
				provider->ssl_verify ? "true" : "false");
	rv = oauth2_cfg_token_verify_add_options(log, &verify, "jwks_uri",
						 provider->jwks_uri, options);
	if (rv != NULL) {
		oauth2_error(
		    log, "oauth2_cfg_token_verify_add_options failed: %s", rv);
		goto end;
	}

	if (oauth2_token_verify(log, verify, s_id_token, &id_token) == false) {
		oauth2_error(log, "id_token verification failed");
		goto end;
	}
	oauth2_cfg_token_verify_free(log, verify);

	if (oauth2_json_string_get(
		log, proto_state,
		_OAUTH2_OPENIDC_PROTO_STATE_KEY_TARGET_LINK_URI, &location,
		NULL) == false)
		goto end;

	if (oauth2_http_response_header_set(
		log, *response, OAUTH2_HTTP_HDR_LOCATION, location) == false)
		goto end;
	if (oauth2_http_response_status_code_set(log, *response, 302) == false)
		goto end;

	rc = true;

	// TODO:
	// validate response
	// create session

end:

	// TODO: json_decref json

	if (redirect_uri)
		oauth2_mem_free(redirect_uri);
	if (options)
		oauth2_mem_free(options);
	if (params)
		oauth2_nv_list_free(log, params);
	if (http_ctx)
		oauth2_http_call_ctx_free(log, http_ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_openidc_is_request_to_redirect_uri(oauth2_log_t *log,
					       const oauth2_cfg_openidc_t *cfg,
					       oauth2_http_request_t *request)
{
	bool rc = false;
	char *redirect_uri = NULL, *request_url;

	request_url = oauth2_http_request_url_path_get(log, request);
	if (request_url == NULL)
		goto end;

	// redirect_uri = oauth2_openidc_cfg_redirect_uri_get_iss(log, cfg,
	// request, provider);
	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, cfg, request);

	oauth2_debug(log, "comparing: \"%s\"=\"%s\"", request_url,
		     redirect_uri);

	if (strcmp(redirect_uri, request_url) != 0)
		goto end;

	rc = true;

end:

	if (request_url)
		oauth2_mem_free(request_url);
	if (redirect_uri)
		oauth2_mem_free(redirect_uri);

	return rc;
}

static bool _oauth2_openidc_internal_requests(oauth2_log_t *log,
					      const oauth2_cfg_openidc_t *cfg,
					      oauth2_http_request_t *request,
					      oauth2_session_rec_t *session,
					      oauth2_http_response_t **response,
					      json_t **claims, bool *processed)
{
	bool rc = true;

	oauth2_debug(log, "enter");

	if (oauth2_openidc_is_request_to_redirect_uri(log, cfg, request) ==
	    true) {
		rc = _oauth2_openidc_redirect_uri_handler(
		    log, cfg, request, session, response, claims);
		*processed = true;
		goto end;
	}

	// TODO:
	// - session info
	// - key materials
	// - 3rd-party init SSO

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_openidc_handle(oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
			   oauth2_http_request_t *request,
			   oauth2_http_response_t **response, json_t **claims)
{
	bool rc = false, processed = false;
	oauth2_session_rec_t *session = NULL;

	oauth2_debug(log, "incoming request: %s%s%s",
		     oauth2_http_request_path_get(log, request),
		     oauth2_http_request_query_get(log, request) ? "?" : "",
		     oauth2_http_request_query_get(log, request)
			 ? oauth2_http_request_query_get(log, request)
			 : "");

	if (oauth2_session_load(log, cfg, request, &session) == false)
		goto end;

	rc = _oauth2_openidc_internal_requests(log, cfg, request, session,
					       response, claims, &processed);
	if ((processed == true) || (rc == false))
		goto end;

	if (oauth2_session_rec_user_get(log, session) != NULL) {
		rc = _oauth2_openidc_existing_session(
		    log, cfg, request, session, response, claims);
		goto end;
	}

	rc = _oauth2_openidc_unauthenticated_request(log, cfg, request, session,
						     response);

end:

	oauth2_session_rec_free(log, session);

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

_OAUTH2_CFG_CTX_TYPE_SINGLE_STRING(oauth2_openidc_provider_resolver_file_ctx,
				   filename)

static bool
_oauth2_openidc_provider_metadata_parse(oauth2_log_t *log, const char *s_json,
					oauth2_openidc_provider_t **provider)
{
	bool rc = false;
	json_t *json = NULL;
	oauth2_openidc_provider_t *p = NULL;
	char *rv = NULL, *token_endpoint_auth = NULL;

	oauth2_debug(log, "enter");

	if (oauth2_json_decode_object(log, s_json, &json) == false) {
		oauth2_error(log, "could not parse json object");
		goto end;
	}

	*provider = oauth2_openidc_provider_init(log);
	p = *provider;
	if (p == NULL)
		goto end;

	if (oauth2_json_string_get(log, json, "issuer", &p->issuer, NULL) ==
	    false) {
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
	if (oauth2_json_string_get(log, json, "jwks_uri", &p->jwks_uri, NULL) ==
	    false) {
		oauth2_error(log, "could not parse jwks_uri");
		goto end;
	}

	p->ssl_verify = json_is_true(json_object_get(json, "ssl_verify"));

	if (oauth2_json_string_get(log, json, "token_endpoint_auth",
				   &token_endpoint_auth,
				   "client_secret_basic") == false) {
		oauth2_error(log, "could not parse token_endpoint_auth");
		goto end;
	}

	// TODO: client file?

	if (oauth2_json_string_get(log, json, "client_id", &p->client_id,
				   NULL) == false) {
		oauth2_error(log, "could not parse client_id");
		goto end;
	}
	if (oauth2_json_string_get(log, json, "client_secret",
				   &p->client_secret, NULL) == false) {
		oauth2_error(log, "could not parse client_secret");
		goto end;
	}
	if (oauth2_json_string_get(log, json, "scope", &p->scope, "openid") ==
	    false) {
		oauth2_error(log, "could not parse scope");
		goto end;
	}

	// TODO:
	oauth2_nv_list_t *params = oauth2_nv_list_init(log);
	oauth2_nv_list_set(log, params, "client_id", p->client_id);
	oauth2_nv_list_set(log, params, "client_secret", p->client_secret);
	p->token_endpoint_auth = oauth2_cfg_endpoint_auth_init(log);
	rv = oauth2_cfg_endpoint_auth_add_options(log, p->token_endpoint_auth,
						  token_endpoint_auth, params);
	oauth2_nv_list_free(log, params);
	if (rv != NULL)
		goto end;

	rc = true;

end:

	if (json)
		json_decref(json);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

#define OAUTH2_OPENIDC_PROVIDER_RESOLVE_FILENAME_DEFAULT "conf/provider.json"

static bool _oauth2_openidc_provider_resolve_file(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, oauth2_openidc_provider_t **provider)
{
	bool rc = false, must_cache = false;
	oauth2_openidc_provider_resolver_file_ctx_t *ctx = NULL;
	char *filename = NULL, *s_json = NULL;

	ctx = (oauth2_openidc_provider_resolver_file_ctx_t *)
		  cfg->provider_resolver->ctx->ptr;
	filename = ctx->filename
		       ? ctx->filename
		       : OAUTH2_OPENIDC_PROVIDER_RESOLVE_FILENAME_DEFAULT;

	// TODO: refactor externalize cache/parse string with callbacks to
	// string data provider
	oauth2_cache_get(log, cfg->provider_resolver->cache->cache, filename,
			 &s_json);

	if (s_json == NULL) {
		s_json = oauth_read_file(log, filename);
		if (s_json == NULL)
			goto end;
		must_cache = true;
	}

	if (_oauth2_openidc_provider_metadata_parse(log, s_json, provider) ==
	    false)
		goto end;

	if (must_cache)
		oauth2_cache_get(log, cfg->provider_resolver->cache->cache,
				 filename, &s_json);

	rc = true;

end:

	if (s_json)
		oauth2_mem_free(s_json);

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

	oauth2_cfg_cache_set_options(log, cfg->provider_resolver->cache,
				     "resolver", params,
				     OAUTH2_CFG_OPENIDC_PROVIDER_CACHE_DEFAULT);

	return NULL;
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
    const oauth2_http_request_t *request, oauth2_openidc_provider_t **provider)
{
	bool rc = false;
	oauth2_openidc_provider_resolver_str_ctx_t *ctx = NULL;

	ctx = (oauth2_openidc_provider_resolver_str_ctx_t *)
		  cfg->provider_resolver->ctx->ptr;
	if (ctx->metadata == NULL) {
		oauth2_error(log, "metadata not configured");
		goto end;
	}

	rc = _oauth2_openidc_provider_metadata_parse(log, ctx->metadata,
						     provider);

end:

	return rc;
}

char *_oauth2_cfg_openidc_provider_resolver_string_set_options(
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

// clang-format off
static oauth2_cfg_set_options_ctx_t _oauth2_cfg_resolver_options_set[] = {
	{ OAUTH2_OPENIDC_PROVIDER_RESOLVER_STR_STR, _oauth2_cfg_openidc_provider_resolver_string_set_options },
	{ OAUTH2_OPENIDC_PROVIDER_RESOLVER_FILE_STR, _oauth2_cfg_openidc_provider_resolver_file_set_options },
	{ OAUTH2_OPENIDC_PROVIDER_RESOLVER_DIR_STR, _oauth2_cfg_openidc_provider_resolver_dir_set_options },
	{ NULL, NULL }
};
// clang-format on

char *oauth2_cfg_openidc_provider_resolver_set_options(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg, const char *type,
    const char *value, const char *options)
{
	return oauth2_cfg_set_options(log, cfg, type, value, options,
				      _oauth2_cfg_resolver_options_set);
}
