#ifndef _OAUTH2_OPENIDC_H_
#define _OAUTH2_OPENIDC_H_

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
 * @file openidc.h
 * @brief OpenID Connect Relying Party (client) flow.
 *
 * Implements the OpenID Connect Authorization Code flow for web servers:
 * oauth2_openidc_handle() dispatches an incoming HTTP request against a
 * location-based configuration (oauth2_cfg_openidc_t) - serving the
 * redirect URI, initiating an authentication request for unauthenticated
 * requests per the configured oauth2_unauth_action_t, and returning the
 * claims associated with an existing session - backed by a cookie-based
 * session store (see session.h).
 */

#include "oauth2/http.h"
#include "oauth2/oauth2.h"
#include "oauth2/util.h"

#define OAUTH2_OPENIDC_ID_TOKEN "id_token"
#define OAUTH2_OPENIDC_ACCESS_TOKEN "access_token"

#define OAUTH2_CLAIM_ISS "iss"

OAUTH2_CFG_TYPE_DECLARE(cfg, session)
OAUTH2_CFG_TYPE_DECLARE(cfg, openidc_provider_resolver)

/**
 * @name Location-based OpenID Connect configuration
 * oauth2_cfg_openidc_t holds the OpenID Connect RP settings for a
 * server location/path: the handler path serving the internal endpoints
 * (the redirect URI lives at "<handler_path>/redirect_uri" by default),
 * the redirect URI itself (absolute, or a path resolved against the
 * incoming request's base URL), the action applied to unauthenticated
 * requests, the state cookie settings that protect the authentication
 * round-trip to the provider, and the associated session configuration.
 * Populate it directly through the accessors below or with the option
 * string parser oauth2_cfg_openidc_set_options().
 * @{
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, openidc)

OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, handler_path, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(cfg, openidc, redirect_uri, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, unauth_action,
				   oauth2_unauth_action_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, session,
				   oauth2_cfg_session_t *)

OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, state_cookie_name_prefix,
				   char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, state_cookie_timeout,
				   oauth2_time_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, state_cookie_max,
				   oauth2_uint_t)
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, openidc, state_cookie_delete_oldest,
			       oauth2_flag_t)

/**
 * @brief Obtain the absolute redirect URI for an incoming request.
 *
 * Returns the configured redirect URI as-is when it is absolute;
 * resolves it against the base URL of the incoming request when it is a
 * path; defaults to "<handler_path>/redirect_uri" under the request's
 * base URL when none was configured.
 *
 * @return the redirect URI as a newly allocated string, to be released
 *         with oauth2_mem_free(), or NULL on error
 */
char *oauth2_cfg_openidc_redirect_uri_get(oauth2_log_t *,
					  const oauth2_cfg_openidc_t *,
					  const oauth2_http_request_t *);
/** @} */

/**
 * @name OpenID Connect protocol state
 * oauth2_openidc_proto_state_t is a name/value object holding the
 * per-authentication-request state - issuer, nonce, PKCE code verifier,
 * original target URL, request method, timestamp - that is serialized
 * into an encrypted state cookie while the user's browser round-trips
 * to the provider's authorization endpoint, and validated against the
 * authorization response on the redirect URI.
 * @{
 */

OAUTH2_TYPE_DECLARE(openidc, proto_state)

oauth2_openidc_proto_state_t *
oauth2_openidc_proto_state_init(oauth2_log_t *log);
oauth2_openidc_proto_state_t *
oauth2_openidc_proto_state_clone(oauth2_log_t *log,
				 const oauth2_openidc_proto_state_t *src);
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
/** @} */

/**
 * @name OpenID Connect provider configuration
 * oauth2_openidc_provider_t holds the settings of the OpenID Connect
 * provider (OP): the issuer and its endpoints. It is obtained at
 * runtime through the configured provider resolver, which produces the
 * provider settings for an incoming request from a JSON document - a
 * static string ("string"), a local file ("file") or a URL ("url",
 * e.g. the provider's Discovery document), cached where applicable.
 * @{
 */

OAUTH2_TYPE_DECLARE(openidc, provider)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, issuer, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, authorization_endpoint,
				   char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, token_endpoint, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, userinfo_endpoint, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, jwks_uri, char *)

bool oauth2_cfg_openidc_provider_resolver_set(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg,
    oauth2_cfg_openidc_provider_resolver_t *resolver);
oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_get(oauth2_log_t *log,
					 const oauth2_cfg_openidc_t *cfg);

/**
 * @brief Configure the provider resolver from an option string.
 *
 * @param log     the log handle to use
 * @param cfg     the OpenID Connect configuration to set the resolver
 *                on
 * @param type    resolver type: "string" (inline JSON provider
 *                document), "file" (path to a JSON file) or "url" (URL
 *                serving the JSON document, e.g. the Discovery endpoint)
 * @param value   the JSON document, filename or URL, per @p type
 * @param options form-encoded parameters, e.g. "cache=<name>" for the
 *                cache that stores resolved documents
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_openidc_provider_resolver_set_options(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg, const char *type,
    const char *value, const char *options);
/** @} */

/**
 * @name OpenID Connect client configuration
 * oauth2_openidc_client_t holds the RP's own registration settings:
 * client identifier and credentials, the scope(s) to request, extra
 * authorization request parameters, the token endpoint authentication
 * method (see oauth2_cfg_endpoint_auth_t in cfg.h) and the outgoing
 * HTTP call settings. Populate it through the accessors below or with
 * oauth2_openidc_client_set_options().
 * @{
 */

OAUTH2_TYPE_DECLARE(openidc, client)

OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, scope, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, authn_request_params,
				   char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, client_id, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, client_secret, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, token_endpoint_auth,
				   oauth2_cfg_endpoint_auth_t *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, ssl_verify, oauth2_flag_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, http_timeout, oauth2_uint_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, http_retries, oauth2_uint_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, http_retry_interval,
				   oauth2_uint_t)

/**
 * @brief Configure the OpenID Connect client from an option string.
 *
 * @param log     the log handle to use
 * @param cfg     the OpenID Connect configuration holding the client
 * @param type    "string" (form-encoded parameters: client_id,
 *                client_secret, scope, authn_request_params,
 *                token_endpoint_auth_method plus the parameters of that
 *                method), "json" (inline JSON client metadata) or
 *                "file" (path to a JSON client metadata file)
 * @param value   the parameter string, JSON document or filename,
 *                per @p type
 * @param options additional form-encoded parameters
 * @return NULL on success, an error string on failure
 */
char *oauth2_openidc_client_set_options(oauth2_log_t *log,
					oauth2_cfg_openidc_t *cfg,
					const char *type, const char *value,
					const char *options);

OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, openidc, client, oauth2_openidc_client_t *)
/** @} */

/**
 * @name OpenID Connect request handling
 * @{
 */

/**
 * @brief Configure the location-based settings from an option string.
 *
 * Parses a form-encoded option string, e.g.
 * "handler_path=/openid-connect&unauth_action=auth", accepting:
 * handler_path, redirect_uri, unauth_action ("auth", "pass", "401" or
 * "410"), state.cookie.name.prefix, state.cookie.timeout (seconds),
 * state.cookie.max and state.cookie.delete.oldest.
 *
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_openidc_set_options(oauth2_log_t *log,
				     oauth2_cfg_openidc_t *cfg,
				     const char *options);

/**
 * @brief Obtain the redirect URI for a request, with an "iss"
 *        parameter identifying the provider appended to it.
 *
 * As oauth2_cfg_openidc_redirect_uri_get(), with the URL-encoded
 * issuer of @p provider added as an "iss" query parameter.
 *
 * @return the redirect URI as a newly allocated string, to be released
 *         with oauth2_mem_free(), or NULL on error
 */
char *oauth2_cfg_openidc_redirect_uri_get_iss(
    oauth2_log_t *, const oauth2_cfg_openidc_t *, const oauth2_http_request_t *,
    const oauth2_openidc_provider_t *);

/**
 * @brief Check whether a request targets the configured redirect URI.
 */
bool oauth2_openidc_is_request_to_redirect_uri(oauth2_log_t *log,
					       const oauth2_cfg_openidc_t *cfg,
					       oauth2_http_request_t *request);

/**
 * @brief Handle an incoming HTTP request according to the OpenID
 *        Connect Authorization Code flow.
 *
 * The main entry point for using liboauth2 as an OpenID Connect RP:
 * loads the session associated with the request, then either serves the
 * internal endpoints (i.e. the authorization response presented on the
 * redirect URI), returns the claims of an existing authenticated
 * session, or applies the configured oauth2_unauth_action_t - by
 * default initiating an authentication request towards the provider.
 *
 * @param log      the log handle to use
 * @param c        the location-based OpenID Connect configuration
 * @param r        the incoming HTTP request
 * @param response set to a newly allocated HTTP response to be served
 *                 to the user agent (redirect, cookies, error status);
 *                 to be released by the caller with
 *                 oauth2_http_response_free()
 * @param claims   on an authenticated request, set to a newly allocated
 *                 JSON object merging the session's id_token and
 *                 userinfo claims; to be released by the caller with
 *                 json_decref()
 *
 * @return true on success, false on error
 */
bool oauth2_openidc_handle(oauth2_log_t *log, const oauth2_cfg_openidc_t *c,
			   oauth2_http_request_t *r,
			   oauth2_http_response_t **response, json_t **claims);
/** @} */

#endif /* _OAUTH2_OPENIDC_H_ */
