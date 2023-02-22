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

#include "oauth2/ipc.h"
#include "oauth2/mem.h"

#include "cache_int.h"
#include "cfg_int.h"
#include "util_int.h"

_OAUTH2_CFG_GLOBAL_LIST(session, oauth2_cfg_session_t)

#define OAUTH2_SESSION_TYPE_COOKIE_STR "cookie"
#define OAUTH2_SESSION_TYPE_CACHE_STR "cache"

oauth2_cfg_session_t *oauth2_cfg_session_init(oauth2_log_t *log)
{
	oauth2_cfg_session_t *session = NULL;
	session = (oauth2_cfg_session_t *)oauth2_mem_alloc(
	    sizeof(oauth2_cfg_session_t));
	session->type = OAUTH2_CFG_UINT_UNSET;
	session->cookie_name = NULL;
	session->cookie_path = NULL;
	session->inactivity_timeout_s = OAUTH2_CFG_TIME_UNSET;
	session->max_duration_s = OAUTH2_CFG_TIME_UNSET;

	session->cache = NULL;

	session->load_callback = NULL;
	session->save_callback = NULL;

	return session;
}
/*
oauth2_cfg_session_t *oauth2_cfg_session_clone(oauth2_log_t *log,
					       oauth2_cfg_session_t *src)
{
	oauth2_cfg_session_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_session_init(log);
	dst->type = src->type;
	dst->cookie_name = oauth2_strdup(src->cookie_name);
	dst->cookie_path = oauth2_strdup(src->cookie_path);
	dst->inactivity_timeout_s = src->inactivity_timeout_s;
	dst->max_duration_s = src->max_duration_s;

	dst->cache = src->cache;

	dst->load_callback = src->load_callback;
	dst->save_callback = src->save_callback;

end:
	return dst;
}
*/
// void oauth2_cfg_session_merge(
//	    oauth2_log_t *log, oauth2_cfg_session_t *cfg,
//	    oauth2_cfg_session_t *add,
//	    oauth2_cfg_session_t *base) {
//}

void oauth2_cfg_session_free(oauth2_log_t *log, oauth2_cfg_session_t *session)
{
	if (session->cookie_name)
		oauth2_mem_free(session->cookie_name);
	if (session->cookie_path)
		oauth2_mem_free(session->cookie_path);
	oauth2_mem_free(session);
}

oauth2_cfg_session_t *_oauth2_cfg_session_obtain(oauth2_log_t *log,
						 const char *name)
{
	oauth2_cfg_session_t *cfg = NULL;

	oauth2_debug(log, "enter: %s", name);

	if (_M_session_list_empty(log)) {
		cfg = oauth2_cfg_session_init(log);
		if (cfg == NULL)
			goto end;
		if (oauth2_cfg_session_set_options(
			log, cfg, OAUTH2_SESSION_TYPE_CACHE_STR, NULL) !=
		    NULL) {
			cfg = NULL;
			goto end;
		}
	}

	cfg = _M_session_list_get(log, name);

end:

	oauth2_debug(log, "leave: %p", cfg);

	return cfg;
}

void _oauth2_session_global_cleanup(oauth2_log_t *log)
{
	oauth2_debug(log, "enter");
	_M_session_list_release(log);
	oauth2_debug(log, "leave");
}

#define OAUTH2_INACTIVITY_TIMEOUT_S_DEFAULT 60 * 5

oauth2_time_t
oauth2_cfg_session_inactivity_timeout_s_get(oauth2_log_t *log,
					    const oauth2_cfg_session_t *cfg)
{
	if ((cfg == NULL) ||
	    (cfg->inactivity_timeout_s == OAUTH2_CFG_TIME_UNSET))
		return OAUTH2_INACTIVITY_TIMEOUT_S_DEFAULT;
	return cfg->inactivity_timeout_s;
}

#define OAUTH2_SESSION_MAX_DURATION_S_DEFAULT 60 * 60 * 8

oauth2_time_t
oauth2_cfg_session_max_duration_s_get(oauth2_log_t *log,
				      const oauth2_cfg_session_t *cfg)
{
	if ((cfg == NULL) || (cfg->max_duration_s == OAUTH2_CFG_TIME_UNSET))
		return OAUTH2_SESSION_MAX_DURATION_S_DEFAULT;
	return cfg->max_duration_s;
}

#define OAUTH2_SESSION_COOKIE_NAME_DEFAULT "openidc_session"

char *oauth2_cfg_session_cookie_name_get(oauth2_log_t *log,
					 const oauth2_cfg_session_t *cfg)
{
	if ((cfg == NULL) || (cfg->cookie_name == NULL))
		return OAUTH2_SESSION_COOKIE_NAME_DEFAULT;
	return cfg->cookie_name;
}

#define OAUTH2_SESSION_COOKIE_PATH_DEFAULT "/"

char *oauth2_cfg_session_cookie_path_get(oauth2_log_t *log,
					 const oauth2_cfg_session_t *cfg)
{
	if ((cfg == NULL) || (cfg->cookie_path == NULL))
		return OAUTH2_SESSION_COOKIE_PATH_DEFAULT;
	return cfg->cookie_path;
}

oauth2_session_load_callback_t *
oauth2_cfg_session_load_callback_get(oauth2_log_t *log,
				     const oauth2_cfg_session_t *cfg)
{
	if ((cfg == NULL) || (cfg->load_callback == NULL))
		return oauth2_session_load_cookie;
	return cfg->load_callback;
}

oauth2_session_save_callback_t *
oauth2_cfg_session_save_callback_get(oauth2_log_t *log,
				     const oauth2_cfg_session_t *cfg)
{
	if ((cfg == NULL) || (cfg->save_callback == NULL))
		return oauth2_session_save_cookie;
	return cfg->save_callback;
}

oauth2_cache_t *oauth2_cfg_session_cache_get(oauth2_log_t *log,
					     const oauth2_cfg_session_t *cfg)
{
	return cfg->cache;
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

	cfg->cache =
	    oauth2_cache_obtain(log, oauth2_nv_list_get(log, params, "cache"));

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

// clang-format off
static oauth2_cfg_set_options_ctx_t _oauth2_cfg_session_options_set[] = {
	{ OAUTH2_SESSION_TYPE_COOKIE_STR, oauth2_cfg_session_set_options_cookie },
	{ OAUTH2_SESSION_TYPE_CACHE_STR, oauth2_cfg_session_set_options_cache },
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

	if (cfg == NULL)
		// global
		cfg = oauth2_cfg_session_init(log);

	rv = oauth2_cfg_set_options(log, cfg, type, NULL, options,
				    _oauth2_cfg_session_options_set);
	if (rv != NULL)
		goto end;

	if (oauth2_parse_form_encoded_params(log, options, &params) == false)
		goto end;

	value = oauth2_nv_list_get(log, params, "cookie.name");
	if (value)
		cfg->cookie_name = oauth2_strdup(value);

	value = oauth2_nv_list_get(log, params, "cookie.path");
	if (value)
		cfg->cookie_path = oauth2_strdup(value);

	value = oauth2_nv_list_get(log, params, "max_duration");
	if (value)
		cfg->max_duration_s =
		    oauth2_parse_time_sec(log, value, OAUTH2_CFG_TIME_UNSET);

	value = oauth2_nv_list_get(log, params, "inactivity_timeout");
	if (value)
		cfg->inactivity_timeout_s =
		    oauth2_parse_time_sec(log, value, OAUTH2_CFG_TIME_UNSET);

	_M_session_list_register(log, oauth2_nv_list_get(log, params, "name"),
				 cfg, oauth2_cfg_session_free);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	return rv;
}
