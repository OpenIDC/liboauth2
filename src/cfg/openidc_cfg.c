/***************************************************************************
 *
 * Copyright (C) 2018-2023 - ZmartZone Holding BV - www.zmartzone.eu
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

#include "oauth2/cfg.h"
#include "oauth2/mem.h"

#include "cfg_int.h"
#include "util_int.h"

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
	c->session = NULL;
	c->client = NULL;

	c->state_cookie_name_prefix = NULL;
	c->state_cookie_timeout = OAUTH2_CFG_TIME_UNSET;
	c->state_cookie_max = OAUTH2_CFG_UINT_UNSET;
	c->state_cookie_delete_oldest = OAUTH2_CFG_FLAG_UNSET;

end:

	return c;
}

oauth2_cfg_openidc_t *oauth2_cfg_openidc_clone(oauth2_log_t *log,
					       const oauth2_cfg_openidc_t *src)
{
	oauth2_cfg_openidc_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_openidc_init(log);
	if (dst == NULL)
		goto end;

	dst->handler_path = oauth2_strdup(src->handler_path);
	dst->redirect_uri = oauth2_strdup(src->redirect_uri);
	dst->provider_resolver = oauth2_cfg_openidc_provider_resolver_clone(
	    log, src->provider_resolver);
	dst->unauth_action = src->unauth_action;
	dst->session = src->session;
	dst->client = oauth2_openidc_client_clone(log, src->client);

	dst->state_cookie_name_prefix =
	    oauth2_strdup(src->state_cookie_name_prefix);
	dst->state_cookie_timeout = src->state_cookie_timeout;
	dst->state_cookie_max = src->state_cookie_max;
	dst->state_cookie_delete_oldest = src->state_cookie_delete_oldest;

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
	cfg->provider_resolver =
	    add->provider_resolver ? oauth2_cfg_openidc_provider_resolver_clone(
					 log, add->provider_resolver)
				   : oauth2_cfg_openidc_provider_resolver_clone(
					 log, base->provider_resolver);
	_OAUTH_CFG_MERGE_VALUE(cfg, base, add, unauth_action,
			       OAUTH2_UNAUTH_ACTION_UNDEFINED)

	cfg->session = add->session ? add->session : base->session;
	cfg->client = add->client
			  ? oauth2_openidc_client_clone(log, add->client)
			  : oauth2_openidc_client_clone(log, base->client);

	_OAUTH_CFG_MERGE_STRING(cfg, base, add, state_cookie_name_prefix);
	_OAUTH_CFG_MERGE_VALUE(cfg, base, add, state_cookie_timeout,
			       OAUTH2_CFG_TIME_UNSET);
	_OAUTH_CFG_MERGE_VALUE(cfg, base, add, state_cookie_max,
			       OAUTH2_CFG_UINT_UNSET);
	_OAUTH_CFG_MERGE_VALUE(cfg, base, add, state_cookie_delete_oldest,
			       OAUTH2_CFG_FLAG_UNSET);

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
	if (c->provider_resolver)
		oauth2_cfg_openidc_provider_resolver_free(log,
							  c->provider_resolver);
	if (c->client)
		oauth2_openidc_client_free(log, c->client);

	if (c->state_cookie_name_prefix)
		oauth2_mem_free(c->state_cookie_name_prefix);

	oauth2_mem_free(c);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, handler_path, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, redirect_uri, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(cfg, openidc, session,
				      oauth2_cfg_session_t *, ptr)

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, state_cookie_name_prefix,
				  char *, str)

#define OAUTH2_OPENIDC_STATE_COOKIE_NAME_PREFIX_DEFAULT "openidc_state_"

char *
oauth2_cfg_openidc_state_cookie_name_prefix_get(oauth2_log_t *log,
						const oauth2_cfg_openidc_t *cfg)
{
	return cfg->state_cookie_name_prefix
		   ? cfg->state_cookie_name_prefix
		   : OAUTH2_OPENIDC_STATE_COOKIE_NAME_PREFIX_DEFAULT;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, state_cookie_timeout,
				  oauth2_time_t, time)

#define OAUTH2_OPENIDC_STATE_COOKIE_TIMEOUT_DEFAULT 300

oauth2_time_t
oauth2_cfg_openidc_state_cookie_timeout_get(oauth2_log_t *log,
					    const oauth2_cfg_openidc_t *cfg)
{
	return cfg->state_cookie_timeout != OAUTH2_CFG_TIME_UNSET
		   ? cfg->state_cookie_timeout
		   : OAUTH2_OPENIDC_STATE_COOKIE_TIMEOUT_DEFAULT;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(cfg, openidc, state_cookie_max, oauth2_uint_t,
				  uint)

#define OAUTH2_OPENIDC_STATE_COOKIE_MAX_DEFAULT 6

oauth2_uint_t
oauth2_cfg_openidc_state_cookie_max_get(oauth2_log_t *log,
					const oauth2_cfg_openidc_t *cfg)
{
	return cfg->state_cookie_max != OAUTH2_CFG_UINT_UNSET
		   ? cfg->state_cookie_max
		   : OAUTH2_OPENIDC_STATE_COOKIE_MAX_DEFAULT;
}

#define OAUTH2_OPENIDC_STATE_COOKIE_DELETE_OLDEST_DEFAULT false

oauth2_flag_t oauth2_cfg_openidc_state_cookie_delete_oldest_get(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg)
{
	return (cfg->state_cookie_delete_oldest != OAUTH2_CFG_FLAG_UNSET)
		   ? cfg->state_cookie_delete_oldest
		   : OAUTH2_OPENIDC_STATE_COOKIE_DELETE_OLDEST_DEFAULT;
}

bool oauth2_cfg_openidc_provider_resolver_set(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg,
    oauth2_cfg_openidc_provider_resolver_t *resolver)
{
	cfg->provider_resolver = resolver;
	return true;
}

oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_get(oauth2_log_t *log,
					 const oauth2_cfg_openidc_t *cfg)
{
	return cfg ? cfg->provider_resolver : NULL;
}

#define OAUTH2_OPENIDC_CFG_HANDLER_PATH_DEFAULT "/openid-connect"

char *oauth2_cfg_openidc_handler_path_get(oauth2_log_t *log,
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
		    NULL, oauth2_cfg_openidc_handler_path_get(log, c),
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

char *oauth2_cfg_openidc_redirect_uri_get_iss(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *c,
    const oauth2_http_request_t *r, const oauth2_openidc_provider_t *provider)
{
	char *redirect_uri = NULL, *issuer = NULL, *sep = NULL, *value = NULL;

	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	if (redirect_uri == NULL)
		goto end;

	// if (provider->issuer_specific_redirect_uri != 0) {

	issuer = oauth2_openidc_provider_issuer_get(log, provider);
	if (issuer)
		value = oauth2_url_encode(log, issuer);

	if (value == NULL)
		goto end;

	sep = strchr(redirect_uri, _OAUTH2_CHAR_QUERY) != NULL
		  ? _OAUTH2_STR_AMP
		  : _OAUTH2_STR_QMARK;
	redirect_uri =
	    _oauth2_stradd4(redirect_uri, sep, "iss", _OAUTH2_STR_EQUAL, value);

end:
	if (value)
		oauth2_mem_free(value);

	return redirect_uri;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(cfg, openidc, unauth_action,
				      oauth2_unauth_action_t, uint)

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(cfg, openidc, client,
				      oauth2_openidc_client_t *, ptr)

/*
 * provider resolver
 */

oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_init(oauth2_log_t *log)
{
	oauth2_cfg_openidc_provider_resolver_t *c = NULL;

	c = oauth2_mem_alloc(sizeof(oauth2_cfg_openidc_provider_resolver_t));
	if (c == NULL)
		goto end;

	c->cache = NULL;
	c->callback = NULL;
	c->ctx = oauth2_cfg_ctx_init(log);

end:

	return c;
}

oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_clone(
    oauth2_log_t *log, const oauth2_cfg_openidc_provider_resolver_t *src)
{
	oauth2_cfg_openidc_provider_resolver_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_openidc_provider_resolver_init(log);
	if (dst == NULL)
		goto end;

	dst->cache = src->cache;
	dst->callback = src->callback;

	// TODO: sort out wrt. _init...
	if (dst->ctx)
		oauth2_cfg_ctx_free(log, dst->ctx);
	dst->ctx = oauth2_cfg_ctx_clone(log, src->ctx);

end:

	return dst;
}

void oauth2_cfg_openidc_provider_resolver_free(
    oauth2_log_t *log, oauth2_cfg_openidc_provider_resolver_t *c)
{
	if (c == NULL)
		goto end;

	if (c->ctx)
		oauth2_cfg_ctx_free(log, c->ctx);

	oauth2_mem_free(c);

end:

	return;
}

char *oauth2_cfg_openidc_set_options(oauth2_log_t *log,
				     oauth2_cfg_openidc_t *cfg,
				     const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;
	const char *value = NULL;

	if (cfg == NULL) {
		rv = oauth2_strdup("struct is null");
		goto end;
	}

	if (oauth2_parse_form_encoded_params(log, options, &params) == false)
		goto end;

	value = oauth2_nv_list_get(log, params, "handler_path");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_openidc_t, handler_path), value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "redirect_uri");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_openidc_t, redirect_uri), value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "state.cookie.name.prefix");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg,
		    offsetof(oauth2_cfg_openidc_t, state_cookie_name_prefix),
		    value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "state.cookie.timeout");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_time_slot(
		    cfg, offsetof(oauth2_cfg_openidc_t, state_cookie_timeout),
		    value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "state.cookie.max");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_uint_slot(
		    cfg, offsetof(oauth2_cfg_openidc_t, state_cookie_max),
		    value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "state.cookie.delete.oldest");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_flag_slot(
		    cfg,
		    offsetof(oauth2_cfg_openidc_t, state_cookie_delete_oldest),
		    value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "unauth_action");
	if (value) {
		if (strncasecmp(value, "auth", 4) == 0)
			oauth2_cfg_openidc_unauth_action_set(
			    log, cfg, OAUTH2_UNAUTH_ACTION_AUTHENTICATE);
		else if (strncasecmp(value, "pass", 4) == 0)
			oauth2_cfg_openidc_unauth_action_set(
			    log, cfg, OAUTH2_UNAUTH_ACTION_PASS);
		else if (strncasecmp(value, "401", 3) == 0)
			oauth2_cfg_openidc_unauth_action_set(
			    log, cfg, OAUTH2_UNAUTH_ACTION_HTTP_401);
		else if (strncasecmp(value, "410", 3) == 0)
			oauth2_cfg_openidc_unauth_action_set(
			    log, cfg, OAUTH2_UNAUTH_ACTION_HTTP_410);
		else {
			rv = oauth2_strdup("unknown value for unauth_action");
			goto end;
		}
	}

end:

	if (params)
		oauth2_nv_list_free(log, params);

	return rv;
}
