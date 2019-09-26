#ifndef _OAUTH2_OPENIDC_INT_H_
#define _OAUTH2_OPENIDC_INT_H_

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

#include "oauth2/openidc.h"

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

bool _oauth2_openidc_state_cookie_get(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    oauth2_http_request_t *request, oauth2_http_response_t *response,
    const char *state, oauth2_openidc_proto_state_t **proto_state);
bool _oauth2_openidc_state_cookie_set(oauth2_log_t *log,
				      const oauth2_cfg_openidc_t *cfg,
				      oauth2_openidc_provider_t *provider,
				      const oauth2_http_request_t *request,
				      oauth2_http_response_t *response,
				      const char *state);
bool _oauth2_openidc_state_validate(oauth2_log_t *log,
				    const oauth2_cfg_openidc_t *cfg,
				    oauth2_http_request_t *request,
				    oauth2_openidc_proto_state_t *proto_state,
				    oauth2_openidc_provider_t **provider);
bool oauth2_openidc_proto_state_target_link_uri_get(
    oauth2_log_t *log, oauth2_openidc_proto_state_t *p, char **value);

bool _oauth2_openidc_provider_resolve(oauth2_log_t *log,
				      const oauth2_cfg_openidc_t *cfg,
				      const oauth2_http_request_t *request,
				      const char *issuer,
				      oauth2_openidc_provider_t **provider);

#endif /* _OAUTH2_OPENIDC_INT_H_ */
