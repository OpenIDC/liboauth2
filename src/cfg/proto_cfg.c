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

typedef struct oauth2_cfg_endpoint_t {
	char *url;
	oauth2_cfg_endpoint_auth_t *auth;
	oauth2_flag_t ssl_verify;
	oauth2_uint_t http_timeout;
} oauth2_cfg_endpoint_t;

oauth2_cfg_endpoint_t *oauth2_cfg_endpoint_init(oauth2_log_t *log)
{
	oauth2_cfg_endpoint_t *endpoint = NULL;

	endpoint = (oauth2_cfg_endpoint_t *)oauth2_mem_alloc(
	    sizeof(oauth2_cfg_endpoint_t));
	if (endpoint == NULL)
		goto end;

	endpoint->url = NULL;
	endpoint->auth = NULL;
	endpoint->ssl_verify = OAUTH2_CFG_FLAG_UNSET;
	endpoint->http_timeout = OAUTH2_CFG_UINT_UNSET;

end:

	return endpoint;
}

void oauth2_cfg_endpoint_free(oauth2_log_t *log,
			      oauth2_cfg_endpoint_t *endpoint)
{
	if (endpoint == NULL)
		goto end;

	if (endpoint->url)
		oauth2_mem_free(endpoint->url);
	if (endpoint->auth)
		oauth2_cfg_endpoint_auth_free(log, endpoint->auth);

	oauth2_mem_free(endpoint);

end:

	return;
}

oauth2_cfg_endpoint_t *oauth2_cfg_endpoint_clone(oauth2_log_t *log,
						 oauth2_cfg_endpoint_t *src)
{
	oauth2_cfg_endpoint_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_endpoint_init(log);
	dst->url = oauth2_strdup(src->url);
	dst->auth = oauth2_cfg_endpoint_auth_clone(log, src->auth);
	dst->ssl_verify = src->ssl_verify;
	dst->http_timeout = src->http_timeout;

end:
	return dst;
}

#define OAUTH2_CFG_ENDPOINT_SSL_VERIFY_DEFAULT 1
#define OAUTH2_CFG_ENDPOINT_HTTP_TIMEOUT_DEFAULT 20

char *oauth2_cfg_set_endpoint_options(oauth2_log_t *log,
				      oauth2_cfg_endpoint_t *cfg,
				      const oauth2_nv_list_t *params)
{
	char *rv = NULL;
	const char *value = NULL;

	if (cfg == NULL) {
		rv = oauth2_strdup("struct is null");
		goto end;
	}

	value = oauth2_nv_list_get(log, params, "url");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_endpoint_t, url), value));
		if (rv)
			goto end;
	}

	cfg->auth = oauth2_cfg_endpoint_auth_init(log);
	rv = oauth2_cfg_endpoint_auth_add_options(
	    log, cfg->auth, oauth2_nv_list_get(log, params, "auth"), params);
	if (rv != NULL)
		goto end;

	value = oauth2_nv_list_get(log, params, "ssl_verify");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_flag_slot(
		    cfg, offsetof(oauth2_cfg_endpoint_t, ssl_verify), value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "http_timeout");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_uint_slot(
		    cfg, offsetof(oauth2_cfg_endpoint_t, http_timeout), value));
		if (rv)
			goto end;
	}

end:

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

const char *oauth2_cfg_endpoint_get_url(const oauth2_cfg_endpoint_t *cfg)
{
	return cfg ? cfg->url : NULL;
}

const oauth2_cfg_endpoint_auth_t *
oauth2_cfg_endpoint_get_auth(const oauth2_cfg_endpoint_t *cfg)
{
	return cfg ? cfg->auth : NULL;
}

oauth2_flag_t
oauth2_cfg_endpoint_get_ssl_verify(const oauth2_cfg_endpoint_t *cfg)
{
	if ((cfg == NULL) || (cfg->ssl_verify == OAUTH2_CFG_FLAG_UNSET))
		return OAUTH2_CFG_ENDPOINT_SSL_VERIFY_DEFAULT;
	return cfg->ssl_verify;
}

oauth2_uint_t
oauth2_cfg_endpoint_get_http_timeout(const oauth2_cfg_endpoint_t *cfg)
{
	if ((cfg == NULL) || (cfg->http_timeout == OAUTH2_CFG_UINT_UNSET))
		return OAUTH2_CFG_ENDPOINT_HTTP_TIMEOUT_DEFAULT;
	return cfg->http_timeout;
}

#define OAUTH2_CFG_ROPC_CLIENT_ID_DEFAULT NULL
#define OAUTH2_CFG_ROPC_USERNAME_DEFAULT NULL
#define OAUTH2_CFG_ROPC_PASSWORD_DEFAULT NULL

typedef struct oauth2_cfg_ropc_t {
	oauth2_cfg_endpoint_t *token_endpoint;
	char *client_id;
	char *username;
	char *password;
} oauth2_cfg_ropc_t;

oauth2_cfg_ropc_t *oauth2_cfg_ropc_init(oauth2_log_t *log)
{
	oauth2_cfg_ropc_t *ropc = NULL;

	ropc = (oauth2_cfg_ropc_t *)oauth2_mem_alloc(sizeof(oauth2_cfg_ropc_t));
	if (ropc == NULL)
		goto end;

	ropc->token_endpoint = NULL;
	ropc->client_id = NULL;
	ropc->username = NULL;
	ropc->password = NULL;

end:

	return ropc;
}

void oauth2_cfg_ropc_free(oauth2_log_t *log, oauth2_cfg_ropc_t *ropc)
{
	if (ropc == NULL)
		goto end;

	if (ropc->token_endpoint)
		oauth2_cfg_endpoint_free(log, ropc->token_endpoint);
	if (ropc->client_id)
		oauth2_mem_free(ropc->client_id);
	if (ropc->username)
		oauth2_mem_free(ropc->username);
	if (ropc->password)
		oauth2_mem_free(ropc->password);

	oauth2_mem_free(ropc);

end:

	return;
}

void oauth2_cfg_ropc_merge(oauth2_log_t *log, oauth2_cfg_ropc_t *dst,
			   oauth2_cfg_ropc_t *base, oauth2_cfg_ropc_t *add)
{

	oauth2_cfg_ropc_t *src =
	    (add && add->token_endpoint != 0) ? add : base ? base : NULL;

	if ((src == NULL) || (dst == NULL))
		goto end;

	dst->token_endpoint =
	    oauth2_cfg_endpoint_clone(log, src->token_endpoint);
	dst->client_id = oauth2_strdup(src->client_id);
	dst->username = oauth2_strdup(src->username);
	dst->password = oauth2_strdup(src->password);

end:

	return;
}

oauth2_cfg_ropc_t *oauth2_cfg_ropc_clone(oauth2_log_t *log,
					 oauth2_cfg_ropc_t *src)
{
	oauth2_cfg_ropc_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_ropc_init(log);
	dst->token_endpoint =
	    oauth2_cfg_endpoint_clone(log, src->token_endpoint);
	dst->client_id = oauth2_strdup(src->client_id);
	dst->username = oauth2_strdup(src->username);
	dst->password = oauth2_strdup(src->password);

end:

	return dst;
}

char *oauth2_cfg_set_ropc_options(oauth2_log_t *log, oauth2_cfg_ropc_t *cfg,
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

	cfg->token_endpoint = oauth2_cfg_endpoint_init(log);
	rv = oauth2_cfg_set_endpoint_options(log, cfg->token_endpoint, params);
	if (rv)
		goto end;

	value = oauth2_nv_list_get(log, params, "client_id");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_ropc_t, client_id), value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "username");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_ropc_t, username), value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "password");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_ropc_t, password), value));
		if (rv)
			goto end;
	}

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

const oauth2_cfg_endpoint_t *
oauth2_cfg_ropc_get_token_endpoint(oauth2_cfg_ropc_t *cfg)
{
	return cfg ? cfg->token_endpoint : NULL;
}

const char *oauth2_cfg_ropc_get_client_id(oauth2_cfg_ropc_t *cfg)
{
	if ((cfg == NULL) || (cfg->client_id == NULL))
		return OAUTH2_CFG_ROPC_CLIENT_ID_DEFAULT;
	return cfg->client_id;
}

const char *oauth2_cfg_ropc_get_username(oauth2_cfg_ropc_t *cfg)
{
	if ((cfg == NULL) || (cfg->username == NULL))
		return OAUTH2_CFG_ROPC_USERNAME_DEFAULT;
	return cfg->username;
}

const char *oauth2_cfg_ropc_get_password(oauth2_cfg_ropc_t *cfg)
{
	if ((cfg == NULL) || (cfg->password == NULL))
		return OAUTH2_CFG_ROPC_PASSWORD_DEFAULT;
	return cfg->password;
}
