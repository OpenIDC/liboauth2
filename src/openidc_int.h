#ifndef _OAUTH2_OPENIDC_INT_H_
#define _OAUTH2_OPENIDC_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2025 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "oauth2/openidc.h"

typedef struct oauth2_openidc_provider_t {
	char *issuer;
	char *authorization_endpoint;
	char *token_endpoint;
	char *jwks_uri;
	char *userinfo_endpoint;
} oauth2_openidc_provider_t;

typedef struct oauth2_openidc_client_t {
	char *client_id;
	char *client_secret;
	char *scope;
	oauth2_cfg_endpoint_auth_t *token_endpoint_auth;
	oauth2_flag_t ssl_verify;
	oauth2_uint_t http_timeout;
	oauth2_openidc_provider_t *provider;
} oauth2_openidc_client_t;

#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_ISSUER "i"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_TARGET_LINK_URI "l"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_REQUEST_METHOD "m"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_MODE "r"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_TYPE "y"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_TIMESTAMP "t"
#define _OAUTH2_OPENIDC_PROTO_STATE_KEY_PKCE "p"

bool _oauth2_openidc_state_cookie_get(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    oauth2_http_request_t *request, oauth2_http_response_t *response,
    const char *state, oauth2_openidc_proto_state_t **proto_state);
bool _oauth2_openidc_state_cookie_set(oauth2_log_t *log,
				      const oauth2_cfg_openidc_t *cfg,
				      oauth2_openidc_provider_t *provider,
				      const oauth2_http_request_t *request,
				      oauth2_http_response_t *response,
				      const char *state, const char *pkce);
bool _oauth2_openidc_state_validate(oauth2_log_t *log,
				    const oauth2_cfg_openidc_t *cfg,
				    oauth2_http_request_t *request,
				    oauth2_openidc_proto_state_t *proto_state,
				    oauth2_openidc_provider_t **provider);
bool oauth2_openidc_proto_state_target_link_uri_get(
    oauth2_log_t *log, oauth2_openidc_proto_state_t *p, char **value);
bool oauth2_openidc_proto_state_pkce_get(oauth2_log_t *log,
					 oauth2_openidc_proto_state_t *p,
					 char **value);

bool _oauth2_openidc_provider_resolve(oauth2_log_t *log,
				      const oauth2_cfg_openidc_t *cfg,
				      const oauth2_http_request_t *request,
				      const char *issuer,
				      oauth2_openidc_provider_t **provider);

#endif /* _OAUTH2_OPENIDC_INT_H_ */
