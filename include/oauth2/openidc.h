#ifndef _OAUTH2_OPENIDC_H_
#define _OAUTH2_OPENIDC_H_

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

/**
 * @name Token response members
 * The members of the token endpoint response (OpenID Connect Core 1.0
 * section 3.1.3.3) that the flow extracts.
 * @{
 */
/** @brief The "id_token" member of the token response. */
#define OAUTH2_OPENIDC_ID_TOKEN "id_token"
/** @brief The "access_token" member of the token response. */
#define OAUTH2_OPENIDC_ACCESS_TOKEN "access_token"
/** @} */

/**
 * @brief The session configuration type of session.h, declared here
 *        for the session member of oauth2_cfg_openidc_t.
 *
 * Only the `_init` and `_free` functions of the declaration are
 * implemented; `_clone` and `_merge` are not.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, session)
/**
 * @brief The provider resolver: the callback that produces the JSON
 *        provider document for an incoming request, its type-specific
 *        context and the cache resolved documents are kept in.
 *
 * Created by oauth2_cfg_openidc_provider_resolver_set_options(); the
 * `_merge` function of the declaration is not implemented.
 */
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

/**
 * @brief The location-based configuration object.
 *
 * `_init` leaves every setting unset so that the getters return the
 * defaults listed below; `_clone` deep-copies the resolver and client
 * and shares the session pointer; `_merge` (for per-location
 * inheritance in the server bindings) takes each setting from the
 * overriding (add) configuration when it is set there and from the
 * base configuration otherwise.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, openidc)

/**
 * @brief The path under which the RP serves its internal endpoints;
 *        the redirect URI is "<handler_path>/redirect_uri" unless
 *        configured explicitly. Default "/openid-connect"; option
 *        "handler_path".
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, handler_path, char *)
/**
 * @brief The redirect URI registered with the provider: an absolute
 *        URL, or a path (starting with "/") that is resolved against
 *        the base URL of each incoming request. Unset by default, so
 *        that "<handler_path>/redirect_uri" is used; option
 *        "redirect_uri". Read it, resolved for a request, with
 *        oauth2_cfg_openidc_redirect_uri_get().
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET(cfg, openidc, redirect_uri, char *)
/**
 * @brief What oauth2_openidc_handle() does with a request that carries
 *        no authenticated session, see oauth2_unauth_action_t
 *        (oauth2.h). Default OAUTH2_UNAUTH_ACTION_UNDEFINED, which
 *        authenticates; option "unauth_action".
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, unauth_action,
				   oauth2_unauth_action_t)
/**
 * @brief The session configuration (session.h) that the sessions
 *        established by the flow are loaded from and saved to. Stored
 *        by reference, not owned: it is one of the registered session
 *        configurations, selected by the "session" option of
 *        oauth2_cfg_openidc_provider_resolver_set_options() and
 *        oauth2_openidc_client_set_options().
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, session,
				   oauth2_cfg_session_t *)

/**
 * @brief The prefix of the state cookie names: a state cookie is named
 *        after the prefix followed by the "state" value of the
 *        authentication request it belongs to. Default
 *        "openidc_state_"; option "state.cookie.name.prefix".
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, state_cookie_name_prefix,
				   char *)
/**
 * @brief The number of seconds an authentication round-trip may take:
 *        the state cookie's max age and the age after which the state
 *        it carries is rejected and the cookie is cleaned up. Default
 *        300; option "state.cookie.timeout".
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, state_cookie_timeout,
				   oauth2_time_t)
/**
 * @brief The maximum number of valid state cookies, i.e. outstanding
 *        authentication round-trips, per browser. Once reached, a new
 *        authentication request fails unless
 *        state_cookie_delete_oldest is set. Default 6; option
 *        "state.cookie.max".
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(cfg, openidc, state_cookie_max,
				   oauth2_uint_t)
/**
 * @brief Whether to clear the oldest state cookie(s) to make room for
 *        a new authentication request when state_cookie_max is
 *        reached, rather than failing it. Default false; only settable
 *        through the "state.cookie.delete.oldest" option.
 */
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
 * Takes the log handle, the location-based configuration and the
 * incoming HTTP request whose base URL (scheme, host and port) a
 * relative redirect URI is resolved against.
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

/**
 * @brief The protocol state object: a JSON object of name/value pairs.
 *        `_init` creates an empty one, `_clone` deep-copies the pairs
 *        and `_free` releases it.
 */
OAUTH2_TYPE_DECLARE(openidc, proto_state)

/**
 * @brief Store a string value in the state, replacing any value stored
 *        under the same name.
 *
 * @param log   the log handle to use
 * @param p     the protocol state
 * @param name  the name to store the value under
 * @param value the string value, copied
 * @return true
 */
bool oauth2_openidc_proto_state_set(oauth2_log_t *log,
				    oauth2_openidc_proto_state_t *p,
				    const char *name, const char *value);
/**
 * @brief Store an integer value in the state, replacing any value
 *        stored under the same name.
 *
 * @param log   the log handle to use
 * @param p     the protocol state
 * @param name  the name to store the value under
 * @param value the integer value
 * @return true
 */
bool oauth2_openidc_proto_state_set_int(oauth2_log_t *log,
					oauth2_openidc_proto_state_t *p,
					const char *name,
					const json_int_t value);
/**
 * @brief Get the JSON object holding the state.
 *
 * @param p the protocol state
 * @return a borrowed pointer to the JSON object, owned by the state
 *         and valid until it is modified or freed
 */
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

/**
 * @brief The provider object, populated from the members of the same
 *        name in the provider's JSON document. Only `_init` and
 *        `_free` are implemented; `_clone` is not.
 */
OAUTH2_TYPE_DECLARE(openidc, provider)
/**
 * @brief The provider's issuer identifier ("issuer"), the one member
 *        the provider document must carry. The "iss" claim of the
 *        id_token must equal it, and it is the key under which the
 *        resolved provider document is cached.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, issuer, char *)
/**
 * @brief The URL of the authorization endpoint
 *        ("authorization_endpoint") the user agent is redirected to
 *        with the authentication request.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, authorization_endpoint,
				   char *)
/**
 * @brief The URL of the token endpoint ("token_endpoint") the
 *        authorization code is exchanged at.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, token_endpoint, char *)
/**
 * @brief The URL of the userinfo endpoint ("userinfo_endpoint") the
 *        userinfo claims are retrieved from with the access token; no
 *        userinfo request is made when it is absent.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, userinfo_endpoint, char *)
/**
 * @brief The URL of the provider's JSON Web Key Set ("jwks_uri") the
 *        id_token signature is verified against.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, jwks_uri, char *)

/**
 * @brief Install a provider resolver on a configuration.
 *
 * The configuration takes ownership of the resolver and releases it
 * with oauth2_cfg_openidc_free(); a different resolver already
 * installed is released first.
 *
 * @param log      the log handle to use
 * @param cfg      the location-based configuration
 * @param resolver the resolver to install
 * @return true, false when cfg is NULL
 */
bool oauth2_cfg_openidc_provider_resolver_set(
    oauth2_log_t *log, oauth2_cfg_openidc_t *cfg,
    oauth2_cfg_openidc_provider_resolver_t *resolver);
/**
 * @brief Get the provider resolver of a configuration.
 *
 * @param log the log handle to use
 * @param cfg the location-based configuration
 * @return a borrowed pointer to the resolver, or NULL when @p cfg is
 *         NULL or no resolver was configured
 */
oauth2_cfg_openidc_provider_resolver_t *
oauth2_cfg_openidc_provider_resolver_get(oauth2_log_t *log,
					 const oauth2_cfg_openidc_t *cfg);

/**
 * @brief Configure the provider resolver from an option string.
 *
 * Replaces the resolver configured before and selects the session
 * configuration of the location. Documents produced by a "file" or
 * "url" resolver are cached under their issuer for 24 hours when a
 * cache is configured; a resolved document must carry an "issuer"
 * member.
 *
 * @param log     the log handle to use
 * @param cfg     the OpenID Connect configuration to set the resolver
 *                on
 * @param type    resolver type: "string" (inline JSON provider
 *                document), "file" (path to a JSON file, default
 *                "conf/provider.json") or "url" (URL serving the JSON
 *                document, e.g. the Discovery endpoint); "dir" is
 *                accepted but not implemented
 * @param value   the JSON document, filename or URL, per @p type
 * @param options form-encoded parameters: "session" names the
 *                registered session configuration (session.h) to use,
 *                the default one when absent; "cache" names the cache
 *                (cache.h) that stores resolved documents, for the
 *                "file" and "url" types; for "url" also the endpoint
 *                settings of oauth2_cfg_set_endpoint() (cfg.h):
 *                "ssl_verify", "http_timeout", "http_retries",
 *                "http_retry_interval" and "outgoing_proxy"
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

/**
 * @brief The client object. `_init` leaves every setting unset,
 *        `_clone` deep-copies it including the token endpoint
 *        authentication and `_free` releases it.
 */
OAUTH2_TYPE_DECLARE(openidc, client)

/**
 * @brief The "scope" parameter of the authentication request, e.g.
 *        "openid profile email"; the getter returns "openid" when
 *        unset. Set by the "scope" parameter or member of
 *        oauth2_openidc_client_set_options().
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, scope, char *)
/**
 * @brief Extra authentication request parameters as a form-encoded
 *        string, e.g. "acr_values=mfa&prompt=login", merged into the
 *        authentication request. Set by the "authn_request_params"
 *        parameter or member of oauth2_openidc_client_set_options().
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, authn_request_params,
				   char *)
/**
 * @brief The client identifier: sent as "client_id" in the
 *        authentication request and required in the "aud" claim of
 *        the id_token. Set by the "client_id" parameter or member of
 *        oauth2_openidc_client_set_options(), which requires it for
 *        the "json" and "file" types.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, client_id, char *)
/**
 * @brief The client secret, for the token endpoint authentication
 *        methods that use one. Set by the "client_secret" parameter or
 *        member of oauth2_openidc_client_set_options().
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, client_secret, char *)
/**
 * @brief The client authentication method and credentials for the
 *        token endpoint, applied to the code exchange with
 *        oauth2_http_ctx_auth_add() (oauth2.h), which fails when it is
 *        NULL: configure "none" for no client authentication. Stored
 *        by reference and owned by the client, released with the
 *        client. Set by the "token_endpoint_auth_method" parameter or
 *        member of oauth2_openidc_client_set_options().
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, token_endpoint_auth,
				   oauth2_cfg_endpoint_auth_t *)
/**
 * @brief Whether to verify the TLS server certificate on the calls to
 *        the token endpoint, the userinfo endpoint and the JWKS URI;
 *        unset counts as true. Set by the "ssl_verify" option of
 *        oauth2_openidc_client_set_options().
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, ssl_verify, oauth2_flag_t)
/**
 * @brief The timeout in seconds of the calls to the token and userinfo
 *        endpoints; the getter returns 20 when unset. There is no
 *        option string for it.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, http_timeout, oauth2_uint_t)
/**
 * @brief The number of times a failed call to the token or userinfo
 *        endpoint is retried. Default 1; there is no option string for
 *        it.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, http_retries, oauth2_uint_t)
/**
 * @brief The interval in milliseconds between those retries. Default
 *        300; there is no option string for it.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, client, http_retry_interval,
				   oauth2_uint_t)

/**
 * @brief Configure the OpenID Connect client from an option string.
 *
 * Creates the client of the configuration when there is none yet,
 * selects the session configuration of the location and applies the
 * "ssl_verify" option before parsing @p value per @p type. For the
 * "string" type the token endpoint authentication method and its
 * parameters (see cfg.h) are taken from @p value; for the "json" and
 * "file" types the method is the "token_endpoint_auth_method" member
 * and its parameters come from @p options, plus the "client_id" and
 * "client_secret" members. A "json" or "file" document that fails to
 * parse leaves the configuration without a client.
 *
 * @param log     the log handle to use
 * @param cfg     the OpenID Connect configuration holding the client
 * @param type    "string" (form-encoded parameters: client_id,
 *                client_secret, scope, authn_request_params,
 *                token_endpoint_auth_method plus the parameters of that
 *                method), "json" (inline JSON client metadata with the
 *                members of the same names, client_id being required)
 *                or "file" (path to a JSON client metadata file)
 * @param value   the parameter string, JSON document or filename,
 *                per @p type
 * @param options form-encoded parameters: "session" names the
 *                registered session configuration (session.h) to use,
 *                the default one when absent; "ssl_verify" ("true" or
 *                "false") sets the client's ssl_verify flag; for the
 *                "json" and "file" types also the parameters of the
 *                token endpoint authentication method
 * @return NULL on success, an error string on failure
 */
char *oauth2_openidc_client_set_options(oauth2_log_t *log,
					oauth2_cfg_openidc_t *cfg,
					const char *type, const char *value,
					const char *options);

/**
 * @brief The client of a location-based configuration: a borrowed
 *        pointer owned by the configuration, or NULL when
 *        oauth2_openidc_client_set_options() has not been called on it.
 */
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
 * state.cookie.max and state.cookie.delete.oldest. Settings absent
 * from the string are left as they are.
 *
 * @param log     the log handle to use
 * @param cfg     the location-based configuration to populate
 * @param options the form-encoded option string
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
 * Takes the log handle, the location-based configuration, the incoming
 * HTTP request and the provider whose issuer is appended.
 *
 * @return the redirect URI as a newly allocated string, to be released
 *         with oauth2_mem_free(), or NULL on error
 */
char *oauth2_cfg_openidc_redirect_uri_get_iss(
    oauth2_log_t *, const oauth2_cfg_openidc_t *, const oauth2_http_request_t *,
    const oauth2_openidc_provider_t *);

/**
 * @brief Check whether a request targets the configured redirect URI.
 *
 * Compares the request's URL, without its query string, to the
 * redirect URI resolved for it with
 * oauth2_cfg_openidc_redirect_uri_get().
 *
 * @param log     the log handle to use
 * @param cfg     the location-based configuration
 * @param request the incoming HTTP request
 * @return true when the request is for the redirect URI
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
 * On the redirect URI the authorization code is exchanged at the token
 * endpoint with the PKCE code verifier from the state cookie, the
 * id_token is verified against the provider's JWKS URI, issuer, the
 * client_id as audience and the nonce, the userinfo claims are
 * retrieved when the provider has a userinfo endpoint, the session is
 * saved with the id_token's "sub" as its user, and the response
 * redirects to the URL originally requested. An authentication request
 * is a 302 redirect to the authorization endpoint carrying a freshly
 * generated state, nonce and PKCE challenge, with the corresponding
 * state cookie set on the response.
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
