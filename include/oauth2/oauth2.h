#ifndef _OAUTH2_H_
#define _OAUTH2_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2026 - ZmartZone Holding BV
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
 * (RFC 6749) and PKCE (RFC 7636): the OpenID Connect RP flow (openidc.h)
 * and the token endpoint grants (proto.h) send them, and the source
 * token retrieval (proto.h) looks for OAUTH2_ACCESS_TOKEN.
 * @{
 */
/** @brief Token request parameter naming the grant (RFC 6749 4.1.3). */
#define OAUTH2_GRANT_TYPE "grant_type"
/**
 * @brief Token response member carrying the access token (RFC 6749
 *        section 5.1); also the default query parameter, form parameter
 *        and cookie name a source token is looked for under (proto.h).
 */
#define OAUTH2_ACCESS_TOKEN "access_token"

/** @brief The authorization code (RFC 6749 sections 4.1.2 and 4.1.3). */
#define OAUTH2_CODE "code"
/** @brief The requested scope (RFC 6749 section 3.3). */
#define OAUTH2_SCOPE "scope"
/**
 * @brief The nonce binding an id_token to the authentication request
 *        (OpenID Connect Core section 3.1.2.1).
 */
#define OAUTH2_NONCE "nonce"
/** @brief The authorization request state (RFC 6749 section 4.1.1). */
#define OAUTH2_STATE "state"
/** @brief The authorization request response type (RFC 6749 3.1.1). */
#define OAUTH2_RESPONSE_TYPE "response_type"
/** @brief The redirection endpoint URI (RFC 6749 section 3.1.2). */
#define OAUTH2_REDIRECT_URI "redirect_uri"
/** @brief OAUTH2_GRANT_TYPE value of the authorization code grant. */
#define OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE "authorization_code"
/** @brief PKCE code challenge (RFC 7636 section 4.3). */
#define OAUTH2_CODE_CHALLENGE "code_challenge"
/** @brief PKCE code challenge method (RFC 7636 section 4.3), "S256". */
#define OAUTH2_CODE_CHALLENGE_METHOD "code_challenge_method"
/** @brief PKCE code verifier sent to the token endpoint (RFC 7636 4.5). */
#define OAUTH2_CODE_VERIFIER "code_verifier"

/** @brief OAUTH2_RESPONSE_TYPE value of the authorization code flow. */
#define OAUTH2_RESPONSE_TYPE_CODE "code"

/** @brief The client identifier (RFC 6749 section 2.2). */
#define OAUTH2_CLIENT_ID "client_id"
/** @brief The client secret as a form parameter (RFC 6749 2.3.1). */
#define OAUTH2_CLIENT_SECRET "client_secret"
/** @} */

/**
 * @name Error response members and error codes
 * Error response member names (RFC 6749 section 5.2), bearer token error
 * codes (RFC 6750 section 3.1) and the step-up authentication challenge
 * error code (RFC 9470). The server bindings put them in the
 * WWW-Authenticate challenge of a rejected request (e.g.
 * oauth2_apache_return_www_authenticate(), apache.h).
 * @{
 */
/** @brief Error response member carrying the error code. */
#define OAUTH2_ERROR "error"
/** @brief Error response member carrying a human-readable description. */
#define OAUTH2_ERROR_DESCRIPTION "error_description"

/** @brief The token is expired, revoked, malformed or otherwise invalid. */
#define OAUTH2_ERROR_INVALID_TOKEN "invalid_token"
/** @brief The request is missing a parameter or otherwise malformed. */
#define OAUTH2_ERROR_INVALID_REQUEST "invalid_request"
/** @brief The token's scope does not cover the requested resource. */
#define OAUTH2_ERROR_INSUFFICIENT_SCOPE "insufficient_scope"
/**
 * @brief The user authentication behind the token does not meet the
 *        resource's requirements, e.g. on ACR or freshness (RFC 9470
 *        section 3).
 */
#define OAUTH2_ERROR_INSUFFICIENT_USER_AUTHENTICATION                          \
	"insufficient_user_authentication"
/** @} */

/**
 * @name JWT claim names
 * Registered JSON Web Token claim names (RFC 7519 section 4.1), as set
 * in the client assertions oauth2_jwt_create() (jose.h) builds and read
 * from DPoP proofs; the names token verification validates are the
 * OAUTH2_JOSE_JWT_* ones in jose.h.
 * @{
 */
/** @brief Issuer. */
#define OAUTH2_CLAIM_ISS "iss"
/** @brief Subject. */
#define OAUTH2_CLAIM_SUB "sub"
/** @brief JWT ID, unique per token; a DPoP proof's replay detection key. */
#define OAUTH2_CLAIM_JTI "jti"
/** @brief Expiration time, in seconds since the epoch. */
#define OAUTH2_CLAIM_EXP "exp"
/** @brief Audience. */
#define OAUTH2_CLAIM_AUD "aud"
/** @brief Issued-at time, in seconds since the epoch. */
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
 * revocation, etc.):
 * - client_secret_basic: HTTP basic authentication on @p ctx with the
 *   URL-encoded client_id and client_secret (RFC 6749 section 2.3.1);
 * - client_secret_post: the "client_id" and "client_secret" form
 *   parameters added to @p params;
 * - client_secret_jwt / private_key_jwt: a "client_assertion" JWT with
 *   the "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
 *   "client_assertion_type" set in @p params (RFC 7523), carrying
 *   "iss" and "sub" set to the client_id, the configured "aud", a "jti"
 *   and an "iat" and "exp" 60 seconds ahead; signed with HS256 by the
 *   key derived from the client secret, respectively with RS256 by the
 *   configured private key, which must be an RSA key;
 * - client_cert: the configured certificate and key files set as the
 *   TLS client certificate of @p ctx;
 * - basic: HTTP basic authentication on @p ctx with the configured
 *   username and password, for endpoints protected with plain basic
 *   authentication rather than client credentials;
 * - none: nothing.
 *
 * @param log    the log handle to use
 * @param ctx    the HTTP call context to add the authentication to
 * @param auth   the endpoint authentication configuration, populated with
 *               oauth2_cfg_set_endpoint_auth()
 * @param params the form POST parameters of the call, to which the
 *               methods above may add
 *
 * @return true on success (including method "none"), false when @p ctx
 *         or @p auth is NULL, the credentials the method needs are not
 *         configured, the private_key_jwt key is not an RSA key or the
 *         assertion could not be created
 */
bool oauth2_http_ctx_auth_add(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
			      const oauth2_cfg_endpoint_auth_t *auth,
			      oauth2_nv_list_t *params);

/**
 * @brief Verify an OAuth 2.x access token.
 *
 * Runs @p token through the chain of verification methods configured in
 * @p verify, in the order they were added with
 * oauth2_cfg_token_verify_add_options() (cfg.h), until one accepts it.
 * For each method the result cache of that method is consulted first,
 * keyed by the token: a cached payload whose "exp" claim has not passed
 * is returned as is, an expired one is dropped and the method is run
 * again. The methods are:
 * - the key-based ones ("plain", "base64", "base64url", "hex", "pem",
 *   "pubkey", "jwk", "jwks_uri", "eckey_uri" and "aws_alb"): the token
 *   is a JWT whose signature and claims are verified per
 *   oauth2_jose_jwt_verify() (jose.h) against the configured key(s);
 * - "introspect": the token is POSTed to the introspection endpoint
 *   (RFC 7662) as the "token" parameter (or the configured
 *   "introspect.token_param_name") with "token_type_hint=access_token",
 *   the configured extra parameters and the endpoint's authentication
 *   (oauth2_http_ctx_auth_add()); the response must be 2xx, JSON without
 *   an "error" member and carry "active": true;
 * - "metadata": the authorization server metadata (RFC 8414) is fetched
 *   from the configured URL and, when the token is a JWT, the JWKS at
 *   its "jwks_uri" verifies it with the metadata "issuer" as the
 *   expected "iss" unless one was configured; a token that is not a JWT
 *   is introspected at the metadata's "introspection_endpoint".
 * The payload the accepting method produced is stored in its cache for
 * the configured expiry (300 seconds by default).
 *
 * When the accepting method was configured with "type=dpop" the request
 * must carry exactly one DPoP header (RFC 9449) whose JWS has "typ"
 * "dpop+jwt", an asymmetric "alg", a public-only "jwk" header that
 * verifies its signature, "htm" and "htu" claims matching the request
 * method and URL, an "iat" fresh per the "dpop.iat.*" options, a "jti"
 * not seen before (tracked in the "dpop.cache" for "dpop.expiry"), an
 * "ath" equal to the SHA-256 hash of the token, and whose key thumbprint
 * equals the token's "cnf"/"jkt" claim. With "type=mtls" (RFC 8705) the
 * SHA-256 fingerprint of the client certificate the binding stored in
 * the request context under OAUTH2_TLS_CERT_VAR_NAME (http.h) must
 * equal the token's "cnf"/"x5t#S256" claim; with "mtls.policy=optional"
 * a token without such a claim passes, with the default "required" it
 * is rejected.
 *
 * @param log     the log handle to use
 * @param request the incoming HTTP request on which the token was
 *                presented; used for the DPoP/mTLS proof-of-possession
 *                checks (a DPoP check fails without it), may be NULL for
 *                plain bearer tokens
 * @param verify  the token verification configuration, created and
 *                populated with oauth2_cfg_token_verify_add_options()
 * @param token   the access token, as presented by the client
 * @param json_payload set to the token's JSON payload, i.e. the JWT
 *                claims or the introspection response, as a new object
 *                to be released by the caller with json_decref(); must
 *                not be NULL. It is set when a method accepted the
 *                token and released again, and set to NULL, when the
 *                proof-of-possession check failed afterwards
 * @param status_code optional (may be NULL); on failure set to the HTTP
 *                status code that the caller is to return, which is
 *                always an error code i.e. 4xx or 5xx, defaulting to 401
 *                when the failure is not the result of a call to a remote
 *                endpoint that returned an error status code itself
 *
 * @return true when the token was verified successfully, false when
 *         @p verify or @p token is NULL, no method accepted the token or
 *         the proof-of-possession check failed
 */
bool oauth2_token_verify(oauth2_log_t *log, oauth2_http_request_t *request,
			 oauth2_cfg_token_verify_t *verify, const char *token,
			 json_t **json_payload,
			 oauth2_http_status_code_t *status_code);

#endif /* _OAUTH2_H_ */
