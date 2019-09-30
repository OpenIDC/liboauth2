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

#define OAUTH2_OPENIDC_ID_TOKEN "id_token"

#define OAUTH2_CLAIM_ISS "iss"

OAUTH2_CFG_TYPE_DECLARE(cfg, openidc_provider_resolver)

/*
 * location-based OpenID Connect configuration
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, openidc)

OAUTH2_TYPE_DECLARE_MEMBER_SET(cfg, openidc, handler_path, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(cfg, openidc, redirect_uri, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, unauth_action,
				   oauth2_unauth_action_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, state_cookie_name_prefix,
				   char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, passphrase, char *)

char *oauth2_cfg_openidc_redirect_uri_get(oauth2_log_t *,
					  const oauth2_cfg_openidc_t *,
					  const oauth2_http_request_t *);

/*
 * protocol state
 */

OAUTH2_TYPE_DECLARE(openidc, proto_state)

oauth2_openidc_proto_state_t *
oauth2_openidc_proto_state_init(oauth2_log_t *log);
oauth2_openidc_proto_state_t *
oauth2_openidc_proto_state_clone(oauth2_log_t *log,
				 oauth2_openidc_proto_state_t *src);
void oauth2_openidc_proto_state_free(oauth2_log_t *log,
				     oauth2_openidc_proto_state_t *p);
bool oauth2_openidc_proto_state_set(oauth2_log_t *log,
				    oauth2_openidc_proto_state_t *p,
				    const char *name, const char *value);
bool oauth2_openidc_proto_state_set_int(oauth2_log_t *log,
					oauth2_openidc_proto_state_t *p,
					const char *name,
					const json_int_t value);
json_t *
oauth2_openidc_proto_state_json_get(const oauth2_openidc_proto_state_t *p);

/*
 * OpenID Connect provider configuration
 */

OAUTH2_TYPE_DECLARE(openidc, provider)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, issuer, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, authorization_endpoint,
				   char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, token_endpoint, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, token_endpoint_auth,
				   oauth2_cfg_endpoint_auth_t *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, jwks_uri, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, scope, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, client_id, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, client_secret, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, ssl_verify, bool)

bool oauth2_cfg_openidc_provider_resolver_set(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg,
    oauth2_cfg_openidc_provider_resolver_t *resolver);
oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_get(oauth2_log_t *log,
					 const oauth2_cfg_openidc_t *cfg);

char *oauth2_cfg_openidc_provider_resolver_set_options(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg, const char *type,
    const char *value, const char *options);

char *oauth2_cfg_openidc_redirect_uri_get_iss(
    oauth2_log_t *, const oauth2_cfg_openidc_t *, const oauth2_http_request_t *,
    const oauth2_openidc_provider_t *);

bool oauth2_openidc_is_request_to_redirect_uri(oauth2_log_t *log,
					       const oauth2_cfg_openidc_t *cfg,
					       oauth2_http_request_t *request);

bool oauth2_openidc_handle(oauth2_log_t *log, const oauth2_cfg_openidc_t *c,
			   oauth2_http_request_t *r,
			   oauth2_http_response_t **response, json_t **claims);

#endif /* _OAUTH2_OPENIDC_H_ */
