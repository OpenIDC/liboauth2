#ifndef _OAUTH2_OPENIDC_H_
#define _OAUTH2_OPENIDC_H_

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

#include "oauth2/http.h"
#include "oauth2/oauth2.h"
#include "oauth2/util.h"

#define OAUTH2_OPENIDC_STATE_COOKIE_NAME_PREFIX_DEFAULT "openidc_state_"

typedef struct oauth2_openidc_provider_t oauth2_openidc_provider_t;
typedef bool(oauth2_openidc_provider_resolver_t)(oauth2_log_t *log,
						 const oauth2_http_request_t *,
						 oauth2_openidc_provider_t **);

/*
 * location-based OpenID Connect configuration
 */

OAUTH2_TYPE_DECLARE(openidc, cfg)
OAUTH2_TYPE_DECLARE_MEMBER_SET(openidc, cfg, handler_path, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(openidc, cfg, redirect_uri, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, cfg, unauth_action,
				   oauth2_unauth_action_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, cfg, state_cookie_name_prefix,
				   char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, cfg, passphrase, char *)

bool oauth2_openidc_cfg_provider_resolver_set(
    oauth2_log_t *, oauth2_openidc_cfg_t *,
    oauth2_openidc_provider_resolver_t *);
oauth2_openidc_provider_resolver_t *
oauth2_openidc_cfg_provider_resolver_get(oauth2_log_t *,
					 const oauth2_openidc_cfg_t *);

char *oauth2_openidc_cfg_redirect_uri_get(oauth2_log_t *,
					  const oauth2_openidc_cfg_t *,
					  const oauth2_http_request_t *);

/*
 * OpenID Connect provider configuration
 */

OAUTH2_TYPE_DECLARE(openidc, provider)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, issuer, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, authorization_endpoint,
				   char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, scope, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, client_id, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, client_secret, char *)

char *oauth2_openidc_cfg_redirect_uri_get_iss(
    oauth2_log_t *, const oauth2_openidc_cfg_t *, const oauth2_http_request_t *,
    const oauth2_openidc_provider_t *);

bool oauth2_openidc_handle(oauth2_log_t *log, const oauth2_openidc_cfg_t *c,
			   oauth2_http_request_t *r,
			   oauth2_http_response_t **response);

#endif /* _OAUTH2_OPENIDC_H_ */
