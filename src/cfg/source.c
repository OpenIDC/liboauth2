/***************************************************************************
 *
 * Copyright (C) 2018-2020 - ZmartZone Holding BV - www.zmartzone.eu
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
#include <cfg_int.h>

#define OAUTH2_CFG_SOURCE_TOKEN_STRIP_DEFAULT (oauth2_flag_t) true

#define OAUTH2_CFG_SOURCE_TOKEN_ACCEPT_IN_DEFAULT                              \
	(OAUTH2_CFG_TOKEN_IN_ENVVAR | OAUTH2_CFG_TOKEN_IN_HEADER)

static char *
oauth2_cfg_accept_in_envvar_options_set(oauth2_log_t *log,
					oauth2_cfg_token_in_t *accept_in,
					const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	accept_in->envvar.name =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "name"));

	return rv;
}

static char *
oauth2_cfg_accept_in_header_options_set(oauth2_log_t *log,
					oauth2_cfg_token_in_t *accept_in,
					const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	accept_in->header.name =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "name"));
	accept_in->header.type =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "type"));

	return rv;
}

static char *
oauth2_cfg_accept_in_query_options_set(oauth2_log_t *log,
				       oauth2_cfg_token_in_t *accept_in,
				       const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	accept_in->query.param_name =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "name"));

	return rv;
}

static char *
oauth2_cfg_accept_in_post_options_set(oauth2_log_t *log,
				      oauth2_cfg_token_in_t *accept_in,
				      const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	accept_in->post.param_name =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "name"));

	return rv;
}

static char *
oauth2_cfg_accept_in_cookie_options_set(oauth2_log_t *log,
					oauth2_cfg_token_in_t *accept_in,
					const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	accept_in->cookie.name =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "name"));

	return rv;
}

typedef char *(oauth2_cfg_accept_token_in_set_options_cb_t)(
    oauth2_log_t *log, oauth2_cfg_token_in_t *accept_in,
    const oauth2_nv_list_t *params);

typedef struct oauth2_cfg_accept_token_in_set_options_ctx_t {
	const char *method;
	oauth2_cfg_token_in_type_t type;
	oauth2_cfg_accept_token_in_set_options_cb_t *options_callback;
} oauth2_cfg_accept_token_in_set_options_ctx_t;

// clang-format off
static oauth2_cfg_accept_token_in_set_options_ctx_t _oauth2_cfg_accept_in_options_set[] = {
	{ OAUTH2_CFG_TOKEN_IN_ENVVAR_STR,	OAUTH2_CFG_TOKEN_IN_ENVVAR,	oauth2_cfg_accept_in_envvar_options_set },
	{ OAUTH2_CFG_TOKEN_IN_HEADER_STR,	OAUTH2_CFG_TOKEN_IN_HEADER,	oauth2_cfg_accept_in_header_options_set },
	{ OAUTH2_CFG_TOKEN_IN_QUERY_STR,	OAUTH2_CFG_TOKEN_IN_QUERY,	oauth2_cfg_accept_in_query_options_set },
	{ OAUTH2_CFG_TOKEN_IN_POST_STR,		OAUTH2_CFG_TOKEN_IN_POST,	oauth2_cfg_accept_in_post_options_set },
	{ OAUTH2_CFG_TOKEN_IN_COOKIE_STR,	OAUTH2_CFG_TOKEN_IN_COOKIE,	oauth2_cfg_accept_in_cookie_options_set },
	{ OAUTH2_CFG_TOKEN_IN_BASIC_STR,	OAUTH2_CFG_TOKEN_IN_BASIC,	NULL },
	{ NULL, 							0,							NULL }
};
// clang-format on

char *oauth2_cfg_token_in_set(oauth2_log_t *log, oauth2_cfg_token_in_t *cfg,
			      const char *method,
			      const oauth2_nv_list_t *params,
			      oauth2_uint_t allowed)
{
	char *rv = NULL;
	int i = 0;

	if (method == NULL) {
		rv = oauth2_strdup("Invalid value, method must be set");
		goto end;
	}

	i = 0;
	while (_oauth2_cfg_accept_in_options_set[i].method != NULL) {
		if ((strcmp(_oauth2_cfg_accept_in_options_set[i].method,
			    method) == 0) &&
		    (allowed & _oauth2_cfg_accept_in_options_set[i].type)) {
			cfg->value |= _oauth2_cfg_accept_in_options_set[i].type;
			if (_oauth2_cfg_accept_in_options_set[i]
				.options_callback)
				rv = _oauth2_cfg_accept_in_options_set[i]
					 .options_callback(log, cfg, params);
			goto end;
		}
		i++;
	}

	rv = oauth2_strdup("Invalid value, must be one of: ");
	i = 0;
	while (_oauth2_cfg_accept_in_options_set[i].method != NULL) {
		rv = oauth2_stradd(
		    rv,
		    _oauth2_cfg_accept_in_options_set[i + 1].method == NULL
			? " or "
			: i > 0 ? ", " : "",
		    _oauth2_cfg_accept_in_options_set[i].method, NULL);
		i++;
	}
	rv = oauth2_stradd(rv, ".", NULL, NULL);

end:

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

#define OAUTH2_CFG_SET_TAKE1_IMPL(ctype, name, member, type)                   \
	const char *oauth2_cfg_set_##name##_##member(                          \
	    oauth2_log_t *log, ctype *cfg, const char *value)                  \
	{                                                                      \
		return oauth2_cfg_set_##type##_slot(                           \
		    cfg, offsetof(ctype, member), value);                      \
	}

OAUTH2_CFG_SET_TAKE1_IMPL(oauth2_cfg_source_token_t, source_token, strip, flag)

oauth2_flag_t oauth2_cfg_source_token_get_strip(oauth2_cfg_source_token_t *cfg)
{
	if (cfg->strip == OAUTH2_CFG_FLAG_UNSET)
		return OAUTH2_CFG_SOURCE_TOKEN_STRIP_DEFAULT;
	return cfg->strip;
}

char *oauth2_cfg_source_token_set_accept_in(oauth2_log_t *log,
					    oauth2_cfg_source_token_t *cfg,
					    const char *method,
					    const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;
	static oauth2_uint_t allowed =
	    OAUTH2_CFG_TOKEN_IN_ENVVAR | OAUTH2_CFG_TOKEN_IN_HEADER |
	    OAUTH2_CFG_TOKEN_IN_QUERY | OAUTH2_CFG_TOKEN_IN_POST |
	    OAUTH2_CFG_TOKEN_IN_COOKIE | OAUTH2_CFG_TOKEN_IN_BASIC;
	const char *strip = NULL;

	if (cfg == NULL) {
		rv = oauth2_strdup("struct is null");
		goto end;
	}

	if (oauth2_parse_form_encoded_params(log, options, &params) == false)
		goto end;

	rv = oauth2_cfg_token_in_set(log, &cfg->accept_in, method, params,
				     allowed);
	if (rv != NULL)
		goto end;

	strip = oauth2_nv_list_get(log, params, "strip");
	if (strip == NULL)
		goto end;

	rv = oauth2_strdup(oauth2_cfg_set_source_token_strip(log, cfg, strip));

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

char oauth2_cfg_source_token_get_accept_in(oauth2_cfg_source_token_t *cfg)
{
	if (cfg->accept_in.value == 0)
		return OAUTH2_CFG_SOURCE_TOKEN_ACCEPT_IN_DEFAULT;
	return cfg->accept_in.value;
}

oauth2_cfg_source_token_t *oauth2_cfg_source_token_init(oauth2_log_t *log)
{
	oauth2_cfg_source_token_t *cfg =
	    (oauth2_cfg_source_token_t *)oauth2_mem_alloc(
		sizeof(oauth2_cfg_source_token_t));
	cfg->accept_in.value = 0;
	cfg->accept_in.query.param_name = NULL;
	cfg->accept_in.post.param_name = NULL;
	cfg->accept_in.cookie.name = NULL;
	cfg->accept_in.envvar.name = NULL;
	cfg->accept_in.header.name = NULL;
	cfg->accept_in.header.type = NULL;
	cfg->strip = OAUTH2_CFG_FLAG_UNSET;
	// cfg->encryption_keys = NULL;
	return cfg;
}

void oauth2_cfg_source_token_free(oauth2_log_t *log,
				  oauth2_cfg_source_token_t *cfg)
{
	if (cfg == NULL)
		goto end;

	if (cfg->accept_in.query.param_name)
		oauth2_mem_free(cfg->accept_in.query.param_name);
	if (cfg->accept_in.post.param_name)
		oauth2_mem_free(cfg->accept_in.post.param_name);
	if (cfg->accept_in.cookie.name)
		oauth2_mem_free(cfg->accept_in.cookie.name);
	if (cfg->accept_in.envvar.name)
		oauth2_mem_free(cfg->accept_in.envvar.name);
	if (cfg->accept_in.header.name)
		oauth2_mem_free(cfg->accept_in.header.name);
	if (cfg->accept_in.header.type)
		oauth2_mem_free(cfg->accept_in.header.type);

	oauth2_mem_free(cfg);

end:

	return;
}

oauth2_cfg_source_token_t *
oauth2_cfg_source_token_clone(oauth2_log_t *log, oauth2_cfg_source_token_t *src)
{
	oauth2_cfg_source_token_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_source_token_init(log);

	dst->accept_in.value = src->accept_in.value;
	dst->accept_in.query.param_name =
	    oauth2_strdup(src->accept_in.query.param_name);
	dst->accept_in.post.param_name =
	    oauth2_strdup(src->accept_in.post.param_name);
	dst->accept_in.cookie.name = oauth2_strdup(src->accept_in.cookie.name);
	dst->accept_in.envvar.name = oauth2_strdup(src->accept_in.envvar.name);
	dst->accept_in.header.name = oauth2_strdup(src->accept_in.header.name);
	dst->accept_in.header.type = oauth2_strdup(src->accept_in.header.type);
	dst->strip = src->strip;

end:

	return dst;
}

void oauth2_cfg_source_token_merge(oauth2_log_t *log,
				   oauth2_cfg_source_token_t *dst,
				   oauth2_cfg_source_token_t *base,
				   oauth2_cfg_source_token_t *add)
{
	oauth2_cfg_source_token_t *src =
	    (add && add->accept_in.value != 0) ? add : base ? base : NULL;

	if (src == NULL)
		goto end;

	dst->accept_in.value = src->accept_in.value;
	dst->accept_in.query.param_name =
	    oauth2_strdup(src->accept_in.query.param_name);
	dst->accept_in.post.param_name =
	    oauth2_strdup(src->accept_in.post.param_name);
	dst->accept_in.cookie.name = oauth2_strdup(src->accept_in.cookie.name);
	dst->accept_in.envvar.name = oauth2_strdup(src->accept_in.envvar.name);
	dst->accept_in.header.name = oauth2_strdup(src->accept_in.header.name);
	dst->accept_in.header.type = oauth2_strdup(src->accept_in.header.type);
	dst->strip = src->strip;

end:

	return;
}
