#ifndef _OAUTH2_H_
#define _OAUTH2_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
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
#define OAUTH2_ERROR_INSUFFICIENT_USER_AUTHENTICATION                          \
	"insufficient_user_authentication"

#define OAUTH2_CLAIM_ISS "iss"
#define OAUTH2_CLAIM_SUB "sub"
#define OAUTH2_CLAIM_JTI "jti"
#define OAUTH2_CLAIM_EXP "exp"
#define OAUTH2_CLAIM_AUD "aud"
#define OAUTH2_CLAIM_IAT "iat"

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
