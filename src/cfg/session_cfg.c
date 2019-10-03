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

#include "oauth2/mem.h"

#include "cfg_int.h"

oauth2_cfg_session_t *oauth2_cfg_session_init(oauth2_log_t *log)
{
	oauth2_cfg_session_t *session = NULL;
	session = (oauth2_cfg_session_t *)oauth2_mem_alloc(
	    sizeof(oauth2_cfg_session_t));
	session->type = OAUTH2_CFG_UINT_UNSET;
	session->cookie_name = NULL;
	session->inactivity_timeout_s = OAUTH2_CFG_UINT_UNSET;
	session->expiry_s = OAUTH2_CFG_UINT_UNSET;
	session->cache = NULL;
	return session;
}

oauth2_cfg_session_t *oauth2_cfg_session_clone(oauth2_log_t *log,
					       oauth2_cfg_session_t *src)
{
	oauth2_cfg_session_t *dst = NULL;
	dst = oauth2_cfg_session_init(log);
	dst->type = src->type;
	dst->cookie_name = oauth2_strdup(src->cookie_name);
	dst->inactivity_timeout_s = src->inactivity_timeout_s;
	dst->expiry_s = src->expiry_s;
	dst->cache = oauth2_cfg_cache_clone(log, src->cache);
	return dst;
}

// void oauth2_cfg_session_merge(
//	    oauth2_log_t *log, oauth2_cfg_session_t *cfg,
//	    oauth2_cfg_session_t *add,
//	    oauth2_cfg_session_t *base) {
//}

void oauth2_cfg_session_free(oauth2_log_t *log, oauth2_cfg_session_t *session)
{
	if (session->cache)
		oauth2_cfg_cache_free(log, session->cache);
	if (session->cookie_name)
		oauth2_mem_free(session->cookie_name);
	oauth2_mem_free(session);
}

#define OAUTH2_INACTIVITY_TIMEOUT_S_DEFAULT 60 * 5

oauth2_uint_t
oauth2_cfg_session_inactivity_timeout_s_get(oauth2_log_t *log,
					    const oauth2_cfg_session_t *cfg)
{
	if (cfg->inactivity_timeout_s == OAUTH2_CFG_UINT_UNSET)
		return OAUTH2_INACTIVITY_TIMEOUT_S_DEFAULT;
	return cfg->inactivity_timeout_s;
}

#define OAUTH2_SESSION_EXPIRY_S_DEFAULT 60 * 60 * 8

oauth2_uint_t oauth2_cfg_session_expiry_s_get(oauth2_log_t *log,
					      const oauth2_cfg_session_t *cfg)
{
	if (cfg->expiry_s == OAUTH2_CFG_UINT_UNSET)
		return OAUTH2_SESSION_EXPIRY_S_DEFAULT;
	return cfg->expiry_s;
}

#define OAUTH2_SESSION_COOKIE_NAME_DEFAULT "openidc_session"

char *oauth2_cfg_session_cookie_name_get(oauth2_log_t *log,
					 const oauth2_cfg_session_t *cfg)
{
	if (cfg->cookie_name == NULL)
		return OAUTH2_SESSION_COOKIE_NAME_DEFAULT;
	return cfg->cookie_name;
}

// TODO: there most probably should NOT be a default for this setting
#define OAUTH2_SESSION_PASSPHRASE_DEFAULT "blabla1234"

char *oauth2_cfg_session_passphrase_get(oauth2_log_t *log,
					const oauth2_cfg_session_t *cfg)
{
	if (cfg->passphrase == NULL)
		return OAUTH2_SESSION_PASSPHRASE_DEFAULT;
	return cfg->passphrase;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_cfg_session_set_options_cookie)
{
	oauth2_cfg_session_t *cfg = (oauth2_cfg_session_t *)ctx;
	char *rv = NULL;

	oauth2_debug(log, "enter");

	cfg->type = OAUTH2_SESSION_TYPE_COOKIE;
	cfg->load_callback = oauth2_session_load_cookie;
	cfg->save_callback = oauth2_session_save_cookie;

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

#define OAUTH2_CFG_SESSION_CACHE_DEFAULT OAUTH2_SESSION_EXPIRY_S_DEFAULT

_OAUTH_CFG_CTX_CALLBACK(oauth2_cfg_session_set_options_cache)
{
	oauth2_cfg_session_t *cfg = (oauth2_cfg_session_t *)ctx;
	char *rv = NULL;

	oauth2_debug(log, "enter");

	cfg->type = OAUTH2_SESSION_TYPE_CACHE;
	cfg->load_callback = oauth2_session_load_cache;
	cfg->save_callback = oauth2_session_save_cache;
	oauth2_cfg_cache_set_options(log, cfg->cache, "session", params,
				     OAUTH2_CFG_SESSION_CACHE_DEFAULT);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

#define OAUTH2_SESSION_TYPE_COOKIE_STR "cookie"
#define OAUTH2_SESSION_TYPE_COOKIE_CACHE "cache"

// clang-format off
static oauth2_cfg_set_options_ctx_t _oauth2_cfg_session_options_set[] = {
	{ OAUTH2_SESSION_TYPE_COOKIE_STR, oauth2_cfg_session_set_options_cookie },
	{ OAUTH2_SESSION_TYPE_COOKIE_CACHE, oauth2_cfg_session_set_options_cache },
	{ NULL, NULL }
};
// clang-format on

char *oauth2_cfg_session_set_options(oauth2_log_t *log,
				     oauth2_cfg_session_t *cfg,
				     const char *type, const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;
	const char *value = NULL;

	if (cfg == NULL) {
		rv = oauth2_strdup("internal error: cfg is null");
		goto end;
	}

	rv = oauth2_cfg_set_options(log, cfg, type, NULL, options,
				    _oauth2_cfg_session_options_set);
	if (rv != NULL)
		goto end;

	if (oauth2_parse_form_encoded_params(log, options, &params) == false)
		goto end;

	value = oauth2_nv_list_get(log, params, "cookie_name");
	if (value)
		cfg->cookie_name = oauth2_strdup(value);

	value = oauth2_nv_list_get(log, params, "expiry");
	if (value)
		cfg->expiry_s =
		    oauth2_parse_uint(log, value, OAUTH2_CFG_UINT_UNSET);

	value = oauth2_nv_list_get(log, params, "inactivity_timeout");
	if (value)
		cfg->inactivity_timeout_s =
		    oauth2_parse_uint(log, value, OAUTH2_CFG_UINT_UNSET);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	return rv;
}
