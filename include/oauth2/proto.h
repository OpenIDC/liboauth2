#ifndef _OAUTH2_PROTO_H_
#define _OAUTH2_PROTO_H_

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
 * @file proto.h
 * @brief OAuth 2.x protocol exchanges: source token retrieval and the
 *        Resource Owner Password Credentials and Client Credentials
 *        grants.
 *
 * Two halves of what a Resource Server or a token-obtaining client
 * does on the wire. On the incoming side, oauth2_get_source_token()
 * picks the access token a client presented on a request out of the
 * location(s) configured in an oauth2_cfg_source_token_t (cfg.h), for
 * verification with oauth2_token_verify() (oauth2.h). On the outgoing
 * side, oauth2_ropc_exec() and oauth2_cc_exec() obtain an access token
 * from a token endpoint configured in an oauth2_cfg_ropc_t or
 * oauth2_cfg_cc_t (cfg.h), using the HTTP client in http.h and the
 * endpoint's client authentication method (oauth2_http_ctx_auth_add(),
 * oauth2.h).
 */

#include "oauth2/cfg.h"
#include "oauth2/http.h"

/**
 * @name Source token retrieval
 * @{
 */

/**
 * @brief Retrieve the access token presented on an incoming request.
 *
 * Tries the locations enabled in the configuration's accept mask
 * (oauth2_cfg_source_token_get_accept_in(), by default the environment
 * variable and the header) in a fixed order and returns the first
 * token found:
 * - "environment": the environment variable named by the location's
 *   "name" option (default "access_token"), read through the server
 *   binding's oauth2_cfg_env_get_cb callback;
 * - "header": the header named by "name" (default "Authorization"),
 *   whose value must start with the scheme in "type" (default
 *   "bearer", matched case-insensitively; an empty "type" accepts the
 *   whole header value);
 * - "query": the query parameter named by "name" (default
 *   "access_token");
 * - "post": the form parameter named by "name" (default
 *   "access_token") of a form-encoded POST, read through the server
 *   binding's oauth2_cfg_form_post_read_cb callback;
 * - "cookie": the cookie named by "name" (default "access_token");
 * - "basic": the password part of an "Authorization: Basic"
 *   credential.
 *
 * When the configuration's "strip" flag is set (the default), the
 * location the token was taken from is cleared - header, query
 * parameter, cookie or environment variable - so it is not passed on
 * to the target application; stripping a POST parameter is not
 * supported and only logs a warning.
 *
 * @param log        the log handle to use
 * @param cfg        the source token configuration: accepted
 *                   locations, their names and the strip flag
 * @param request    the incoming HTTP request, modified in place when
 *                   the token is stripped
 * @param srv_cb     the server binding's callbacks, used for the
 *                   "environment" and "post" locations
 * @param srv_cb_ctx the context passed to the callbacks (e.g. the
 *                   binding's request context)
 * @return the token as a newly allocated string, to be released with
 *         oauth2_mem_free(), or NULL when none of the enabled
 *         locations carries one
 */
char *oauth2_get_source_token(oauth2_log_t *log, oauth2_cfg_source_token_t *cfg,
			      oauth2_http_request_t *request,
			      oauth2_cfg_server_callback_funcs_t *srv_cb,
			      void *srv_cb_ctx);

/** @} */

/**
 * @name Token endpoint grants
 * Both exchanges POST a form-encoded request to the configured token
 * endpoint with the endpoint's SSL verification, timeout, retry and
 * outgoing proxy settings applied, authenticate to it with the
 * endpoint's client authentication method - adding "client_id" as a
 * plain parameter only when that method is "none" and a client_id is
 * configured - merge in the configured extra request parameters and
 * require a 2xx JSON response carrying an "access_token" member. The
 * token type, expiry and any refresh token in the response are
 * ignored, and results are not cached.
 * @{
 */

/**
 * @brief Obtain an access token with the Resource Owner Password
 *        Credentials grant (RFC 6749 section 4.3).
 *
 * Sends "grant_type=password" with the "username" (omitted when NULL)
 * and "password" parameters.
 *
 * @param log         the log handle to use
 * @param cfg         the ROPC configuration (token endpoint, client_id
 *                    and extra request parameters); the username and
 *                    password stored in it are not used, pass them
 *                    explicitly
 * @param username    the resource owner's username, may be NULL
 * @param password    the resource owner's password
 * @param rtoken      on success, set to the access token as a newly
 *                    allocated string, to be released with
 *                    oauth2_mem_free(); untouched on failure
 * @param status_code set to the HTTP status code of the token endpoint
 *                    response once one was received, also on failure
 * @return true when an access token was obtained, false on a
 *         transport error, a non-2xx response, an error response or a
 *         response without an access token
 */
bool oauth2_ropc_exec(oauth2_log_t *log, oauth2_cfg_ropc_t *cfg,
		      const char *username, const char *password, char **rtoken,
		      oauth2_uint_t *status_code);

/**
 * @brief Obtain an access token with the Client Credentials grant
 *        (RFC 6749 section 4.4).
 *
 * Sends "grant_type=client_credentials"; the client is identified
 * solely by the endpoint's authentication method (or the configured
 * client_id when that method is "none").
 *
 * @param log         the log handle to use
 * @param cfg         the Client Credentials configuration (token
 *                    endpoint, client_id and extra request parameters)
 * @param rtoken      on success, set to the access token as a newly
 *                    allocated string, to be released with
 *                    oauth2_mem_free(); untouched on failure
 * @param status_code set to the HTTP status code of the token endpoint
 *                    response once one was received, also on failure
 * @return true when an access token was obtained, false otherwise
 */
bool oauth2_cc_exec(oauth2_log_t *log, oauth2_cfg_cc_t *cfg, char **rtoken,
		    oauth2_uint_t *status_code);
/** @} */

#endif /* _OAUTH2_PROTO_H_ */
