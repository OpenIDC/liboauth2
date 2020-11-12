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
	c->provider = NULL;
	c->token_endpoint_auth = NULL;
	c->ssl_verify = OAUTH2_CFG_FLAG_UNSET;
	c->http_timeout = OAUTH2_CFG_UINT_UNSET;

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
	if (c->token_endpoint_auth)
		oauth2_cfg_endpoint_auth_free(log, c->token_endpoint_auth);

	oauth2_mem_free(c);

end:

	return;
}

oauth2_openidc_client_t *
oauth2_openidc_client_clone(oauth2_log_t *log, oauth2_openidc_client_t *src)
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
	dst->token_endpoint_auth =
	    oauth2_cfg_endpoint_auth_clone(log, src->token_endpoint_auth);
	dst->ssl_verify = src->ssl_verify;
	dst->http_timeout = src->http_timeout;

end:

	return dst;
}

char *oauth2_openidc_client_set_options(oauth2_log_t *log,
					oauth2_cfg_openidc_t *cfg,
					const char *client_id,
					const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;

	oauth2_debug(log, "enter");

	if (cfg->client) {
		oauth2_openidc_client_free(log, cfg->client);
		cfg->client = NULL;
	}

	oauth2_parse_form_encoded_params(log, options, &params);

	cfg->client = oauth2_openidc_client_init(log);

	oauth2_openidc_client_client_id_set(log, cfg->client, client_id);
	oauth2_openidc_client_client_secret_set(
	    log, cfg->client, oauth2_nv_list_get(log, params, "client_secret"));
	oauth2_openidc_client_scope_set(
	    log, cfg->client, oauth2_nv_list_get(log, params, "scope"));

	rv = oauth2_strdup(oauth2_cfg_set_flag_slot(
	    cfg->client, offsetof(oauth2_openidc_client_t, ssl_verify),
	    oauth2_nv_list_get(log, params, "ssl_verify")));
	if (rv != NULL)
		goto end;

	auth = oauth2_cfg_endpoint_auth_init(log);

	rv = oauth2_cfg_set_endpoint_auth(
	    log, auth,
	    oauth2_nv_list_get(log, params, "token_endpoint_auth_method"),
	    params, NULL);

	if (rv == NULL)
		oauth2_openidc_client_token_endpoint_auth_set(log, cfg->client,
							      auth);
	else
		oauth2_cfg_endpoint_auth_free(log, auth);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %d");

	return rv;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, scope, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, client_id, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, client_secret, char *,
				      str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, token_endpoint_auth,
				      oauth2_cfg_endpoint_auth_t *, ptr)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, provider,
				      oauth2_openidc_provider_t *, ptr)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, ssl_verify,
				      oauth2_flag_t, bln)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, client, http_timeout,
				      oauth2_uint_t, uint)
