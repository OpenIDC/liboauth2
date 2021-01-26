#ifndef _OAUTH2_H_
#define _OAUTH2_H_

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

#include <jansson.h>

#include "oauth2/cfg.h"
#include "oauth2/http.h"
#include "oauth2/log.h"
#include "oauth2/util.h"

#define OAUTH2_GRANT_TYPE "grant_type"
#define OAUTH2_ACCESS_TOKEN "access_token"

#define OAUTH2_CODE "code"
#define OAUTH2_SCOPE "scope"
#define OAUTH2_NONCE "nonce"
#define OAUTH2_STATE "state"
#define OAUTH2_RESPONSE_TYPE "response_type"
#define OAUTH2_REDIRECT_URI "redirect_uri"
#define OAUTH2_GRANT_TYPE "grant_type"
#define OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE "authorization_code"
#define OAUTH2_CODE_CHALLENGE "code_challenge"
#define OAUTH2_CODE_CHALLENGE_METHOD "code_challenge_method"
#define OAUTH2_CODE_VERIFIER "code_verifier"

#define OAUTH2_RESPONSE_TYPE_CODE "code"

#define OAUTH2_CLIENT_ID "client_id"
#define OAUTH2_CLIENT_SECRET "client_secret"

#define OAUTH2_ERROR "error"
#define OAUTH2_ERROR_DESCRIPTION "error_description"

#define OAUTH2_ERROR_INVALID_TOKEN "invalid_token"
#define OAUTH2_ERROR_INVALID_REQUEST "invalid_request"
#define OAUTH2_ERROR_INSUFFICIENT_SCOPE "insufficient_scope"

#define OAUTH2_CLAIM_ISS "iss"
#define OAUTH2_CLAIM_SUB "sub"
#define OAUTH2_CLAIM_JTI "jti"
#define OAUTH2_CLAIM_EXP "exp"
#define OAUTH2_CLAIM_AUD "aud"
#define OAUTH2_CLAIM_IAT "iat"

#define OAUTH2_TLS_CERT_VAR_NAME "SSL_CLIENT_CERT"

typedef enum {
	OAUTH2_UNAUTH_ACTION_UNDEFINED,
	OAUTH2_UNAUTH_ACTION_AUTHENTICATE,
	OAUTH2_UNAUTH_ACTION_PASS,
	OAUTH2_UNAUTH_ACTION_HTTP_401,
	OAUTH2_UNAUTH_ACTION_HTTP_410
} oauth2_unauth_action_t;

bool oauth2_http_ctx_auth_add(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
			      const oauth2_cfg_endpoint_auth_t *auth,
			      oauth2_nv_list_t *params);

bool oauth2_token_verify(oauth2_log_t *log, oauth2_http_request_t *request,
			 oauth2_cfg_token_verify_t *verify, const char *token,
			 json_t **json_payload);

#endif /* _OAUTH2_H_ */
