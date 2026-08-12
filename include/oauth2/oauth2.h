#ifndef _OAUTH2_H_
#define _OAUTH2_H_

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

/**
 * @file oauth2.h
 * @brief OAuth 2.x wire protocol constants and access token verification.
 *
 * This is the primary entry point for using liboauth2 as an OAuth 2.x
 * Resource Server: configure one or more verification methods in an
 * oauth2_cfg_token_verify_t (see cfg.h) and pass each access token
 * presented on an incoming HTTP request to oauth2_token_verify().
 */

#include <jansson.h>

#include "oauth2/cfg.h"
#include "oauth2/http.h"
#include "oauth2/log.h"
#include "oauth2/util.h"

/**
 * @name OAuth 2.x protocol parameters
 * Request/response parameter names and values used in OAuth 2.x flows
 * (RFC 6749) and PKCE (RFC 7636).
 * @{
 */
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
/** @} */

/**
 * @name Error response members and error codes
 * Error response member names (RFC 6749 section 5.2), bearer token error
 * codes (RFC 6750 section 3.1) and the step-up authentication challenge
 * error code (RFC 9470).
 * @{
 */
#define OAUTH2_ERROR "error"
#define OAUTH2_ERROR_DESCRIPTION "error_description"

#define OAUTH2_ERROR_INVALID_TOKEN "invalid_token"
#define OAUTH2_ERROR_INVALID_REQUEST "invalid_request"
#define OAUTH2_ERROR_INSUFFICIENT_SCOPE "insufficient_scope"
#define OAUTH2_ERROR_INSUFFICIENT_USER_AUTHENTICATION                          \
	"insufficient_user_authentication"
/** @} */

/**
 * @name JWT claim names
 * Registered JSON Web Token claim names (RFC 7519 section 4.1).
 * @{
 */
#define OAUTH2_CLAIM_ISS "iss"
#define OAUTH2_CLAIM_SUB "sub"
#define OAUTH2_CLAIM_JTI "jti"
#define OAUTH2_CLAIM_EXP "exp"
#define OAUTH2_CLAIM_AUD "aud"
#define OAUTH2_CLAIM_IAT "iat"
/** @} */

/**
 * @brief Action to apply to a request that is not (yet) authenticated.
 *
 * Consumed by the OpenID Connect RP handling (see openidc.h) and the
 * server bindings to decide how to respond to a request that carries no
 * valid session or token.
 */
typedef enum {
	/**
	 * No action configured: behaves as
	 * OAUTH2_UNAUTH_ACTION_AUTHENTICATE.
	 */
	OAUTH2_UNAUTH_ACTION_UNDEFINED,
	/**
	 * Initiate an OpenID Connect authentication request towards the
	 * provider; XML HTTP (Ajax) requests receive a 410 instead since
	 * they cannot meaningfully follow the redirect.
	 */
	OAUTH2_UNAUTH_ACTION_AUTHENTICATE,
	/** Pass the request on to the application, unauthenticated. */
	OAUTH2_UNAUTH_ACTION_PASS,
	/** Reject the request with HTTP status 401 Unauthorized. */
	OAUTH2_UNAUTH_ACTION_HTTP_401,
	/** Reject the request with HTTP status 410 Gone. */
	OAUTH2_UNAUTH_ACTION_HTTP_410
} oauth2_unauth_action_t;

/**
 * @brief Add client authentication to an outgoing HTTP call.
 *
 * Applies the endpoint authentication method configured in @p auth to a
 * call towards an OAuth 2.x server endpoint (token, introspection,
 * revocation, etc.): client_secret_basic, client_secret_post,
 * client_secret_jwt, private_key_jwt, a TLS client certificate, or plain
 * HTTP basic authentication. Depending on the method this modifies the
 * call context @p ctx (headers, TLS settings) and/or appends form POST
 * parameters to @p params.
 *
 * @param log    the log handle to use
 * @param ctx    the HTTP call context to add the authentication to
 * @param auth   the endpoint authentication configuration, populated with
 *               oauth2_cfg_set_endpoint_auth()
 * @param params list to which authentication form POST parameters (e.g.
 *               client_id/client_secret or a client assertion JWT) may be
 *               appended
 *
 * @return true on success (including method "none"), false on error
 */
bool oauth2_http_ctx_auth_add(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
			      const oauth2_cfg_endpoint_auth_t *auth,
			      oauth2_nv_list_t *params);

/**
 * @brief Verify an OAuth 2.x access token.
 *
 * Runs @p token through the chain of verification methods configured in
 * @p verify until one succeeds, e.g. local JWT signature verification
 * against a configured key, JWKS URI or (discovered) authorization server
 * metadata, or remote token introspection (RFC 7662). A successful result
 * is cached in the cache associated with the succeeding method; a cache
 * hit is re-validated against the token's "exp" claim. If the succeeding
 * method is configured for proof-of-possession, the corresponding DPoP
 * (RFC 9449) or mTLS (RFC 8705) sender-constraint checks are applied
 * against @p request as well.
 *
 * @param log     the log handle to use
 * @param request the incoming HTTP request on which the token was
 *                presented; used for the DPoP/mTLS proof-of-possession
 *                checks, may be NULL for plain bearer tokens
 * @param verify  the token verification configuration, created and
 *                populated with oauth2_cfg_token_verify_add_options()
 * @param token   the access token, as presented by the client
 * @param json_payload on success set to the token's JSON payload, i.e.
 *                the JWT claims or the introspection response; to be
 *                released by the caller with json_decref()
 * @param status_code optional (may be NULL); on failure set to the HTTP
 *                status code that the caller is to return, which is
 *                always an error code i.e. 4xx or 5xx, defaulting to 401
 *                when the failure is not the result of a call to a remote
 *                endpoint that returned an error status code itself
 *
 * @return true when the token was verified successfully, false otherwise
 */
bool oauth2_token_verify(oauth2_log_t *log, oauth2_http_request_t *request,
			 oauth2_cfg_token_verify_t *verify, const char *token,
			 json_t **json_payload,
			 oauth2_http_status_code_t *status_code);

#endif /* _OAUTH2_H_ */
