#ifndef _OAUTH2_CFG_H_
#define _OAUTH2_CFG_H_

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
 * @file cfg.h
 * @brief The configuration object model.
 *
 * Per-feature configuration objects populated from directive-style
 * option strings: this is how server bindings translate their native
 * configuration directives (e.g. Apache or NGINX ones) into typed
 * settings for the core library. Option strings are form-encoded
 * name/value parameters ("name1=value1&name2=value2"); setters return
 * NULL on success or a string describing the offending option.
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "oauth2/util.h"

/**
 * @name Sentinel values for unset flag/integer/time settings
 * @{
 */
#define OAUTH2_CFG_FLAG_UNSET (oauth2_flag_t) - 1
#define OAUTH2_CFG_UINT_UNSET (oauth2_uint_t) - 1
#define OAUTH2_CFG_TIME_UNSET (oauth2_time_t) - 1
/** @} */

/**
 * @name Generic setter plumbing
 * The slot setters parse a string value into the flag/uint/time/string
 * member at byte @p offset of a configuration struct; bindings use
 * them to implement simple scalar directives. They return NULL on
 * success or a static error string.
 * @{
 */

const char *oauth2_cfg_set_flag_slot(void *cfg, size_t offset,
				     const char *value);
const char *oauth2_cfg_set_uint_slot(void *cfg, size_t offset,
				     const char *value);
const char *oauth2_cfg_set_time_slot(void *cfg, size_t offset,
				     const char *value);
const char *oauth2_cfg_set_str_slot(void *cfg, size_t offset,
				    const char *value);

/**
 * @brief Declare a configuration object type.
 *
 * As OAUTH2_TYPE_DECLARE (util.h), additionally generating an
 * oauth2_<module>_<object>_merge function that combines a base and an
 * overriding (add) configuration into a destination, as used for
 * per-directory/location inheritance in server bindings.
 */
#define OAUTH2_CFG_TYPE_DECLARE(module, object)                                \
	OAUTH2_TYPE_DECLARE(module, object)                                    \
	void oauth2_##module##_##object##_merge(                               \
	    oauth2_log_t *, oauth2_##module##_##object##_t *,                  \
	    oauth2_##module##_##object##_t *,                                  \
	    oauth2_##module##_##object##_t *);

/**
 * @brief Set the global passphrase from which crypto keys are derived,
 *        e.g. for cache and (state) cookie encryption.
 */
const char *oauth2_crypto_passphrase_set(oauth2_log_t *log, void *dummy,
					 const char *passphrase);
const char *oauth2_crypto_passphrase_get(oauth2_log_t *log);
/** @} */

/**
 * @brief Create and register a named cache instance.
 *
 * @param log     the log handle to use
 * @param dummy   ignored
 * @param type    cache backend: "shm" or "file", plus "memcache" and
 *                "redis" when compiled in
 * @param options form-encoded parameters: "name" to register the
 *                instance under (for retrieval with
 *                oauth2_cache_obtain(), see cache.h) plus
 *                backend-specific settings such as "max_entries"
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_cache(oauth2_log_t *log, void *dummy, const char *type,
			   const char *options);

/**
 * @name Webserver callbacks
 * Callbacks that a server binding provides so the core library can
 * read and set environment variables and read form POST data through
 * the hosting server (see apache.h and nginx.h for the bindings'
 * implementations).
 * @{
 */

typedef bool(oauth2_cfg_env_get_cb)(oauth2_log_t *log, void *ctx,
				    const char *key, char **value);
typedef bool(oauth2_cfg_env_set_cb)(oauth2_log_t *log, void *ctx,
				    const char *key, const char *value);
typedef bool(oauth2_cfg_form_post_read_cb)(oauth2_log_t *log, void *ctx,
					   oauth2_nv_list_t **params);

typedef struct oauth2_cfg_server_callback_funcs_t {
	oauth2_cfg_env_get_cb *get;
	oauth2_cfg_env_set_cb *set;
	oauth2_cfg_form_post_read_cb *form_post;
} oauth2_cfg_server_callback_funcs_t;
/** @} */

/**
 * @name Endpoint authentication
 * oauth2_cfg_endpoint_auth_t holds the client authentication method
 * and credentials for calls towards an OAuth 2.x server endpoint
 * (token, introspection, etc.), applied to outgoing calls with
 * oauth2_http_ctx_auth_add() (oauth2.h). Configured as a type with
 * type-specific parameters:
 * @verbatim
 client_secret_basic client_id=<string>&client_secret=<string>
 client_secret_post  client_id=<string>&client_secret=<string>
 client_secret_jwt   client_id=<string>&client_secret=<string>&aud=<string>
 private_key_jwt     jwk=<json>&aud=<string>
 client_cert         cert=<filename>&key=<filename>
 basic               username=<string>&password=<string>
 @endverbatim
 * @{
 */

typedef enum oauth2_cfg_endpoint_auth_type_t {
	OAUTH2_ENDPOINT_AUTH_NONE,
	OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC,
	OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST,
	OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT,
	OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT,
	OAUTH2_ENDPOINT_AUTH_CLIENT_CERT,
	OAUTH2_ENDPOINT_AUTH_BASIC
} oauth2_cfg_endpoint_auth_type_t;

OAUTH2_CFG_TYPE_DECLARE(cfg, endpoint_auth)

/**
 * @brief Configure an endpoint authentication method.
 *
 * @param log    the log handle to use
 * @param auth   the endpoint authentication configuration to populate
 * @param type   one of the method names listed above, or "none"
 * @param params the method-specific parameters listed above
 * @param prefix optional prefix prepended to the parameter names when
 *               looking them up in @p params, may be NULL
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_endpoint_auth(oauth2_log_t *log,
				   oauth2_cfg_endpoint_auth_t *auth,
				   const char *type,
				   const oauth2_nv_list_t *params,
				   const char *prefix);

oauth2_cfg_endpoint_auth_type_t
oauth2_cfg_endpoint_auth_type(const oauth2_cfg_endpoint_auth_t *auth);
/** @} */

/**
 * @name Endpoint settings
 * oauth2_cfg_endpoint_t holds the settings for calling a remote
 * endpoint: its URL, the authentication method/credentials, TLS server
 * certificate verification, HTTP timeout and retry behaviour, and an
 * outgoing proxy.
 * @{
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, endpoint)

char *oauth2_cfg_set_endpoint(oauth2_log_t *log, oauth2_cfg_endpoint_t *cfg,
			      const char *url, const oauth2_nv_list_t *params,
			      const char *prefix);

const char *oauth2_cfg_endpoint_get_url(const oauth2_cfg_endpoint_t *cfg);
void oauth2_cfg_endpoint_set_url(oauth2_cfg_endpoint_t *cfg, const char *url);
const oauth2_cfg_endpoint_auth_t *
oauth2_cfg_endpoint_get_auth(const oauth2_cfg_endpoint_t *cfg);
oauth2_flag_t
oauth2_cfg_endpoint_get_ssl_verify(const oauth2_cfg_endpoint_t *cfg);
oauth2_uint_t
oauth2_cfg_endpoint_get_http_timeout(const oauth2_cfg_endpoint_t *cfg);
oauth2_uint_t
oauth2_cfg_endpoint_get_http_retries(const oauth2_cfg_endpoint_t *cfg);
oauth2_uint_t
oauth2_cfg_endpoint_get_http_retry_interval(const oauth2_cfg_endpoint_t *cfg);
const char *
oauth2_cfg_endpoint_get_outgoing_proxy(const oauth2_cfg_endpoint_t *cfg);
/** @} */

/**
 * @name Token verification
 * oauth2_cfg_token_verify_t is a chain of verification methods for
 * incoming access tokens, consumed by oauth2_token_verify() (oauth2.h),
 * which runs the chain until one method succeeds.
 * @{
 */

/**
 * @brief How a token is presented by the client: as a plain bearer
 *        token (RFC 6750) or bound to the client with DPoP (RFC 9449)
 *        or mTLS (RFC 8705) proof-of-possession.
 */
typedef enum oauth2_cfg_token_verify_type_t {
	OAUTH2_TOKEN_VERIFY_BEARER,
	OAUTH2_TOKEN_VERIFY_DPOP,
	OAUTH2_TOKEN_VERIFY_MTLS
} oauth2_cfg_token_verify_type_t;

OAUTH2_CFG_TYPE_DECLARE(cfg, token_verify)

/**
 * @brief Add a verification method to a token verification chain.
 *
 * Appends a method to *@p verify, creating the chain when it is NULL.
 *
 * @param log the log handle to use
 * @param verify pointer to the chain to add to; the chain is created
 *   when *@p verify is NULL
 * @param type the verification type:
 *   - "plain", "base64", "base64url" or "hex": a symmetric key
 *     provided as a string in that encoding
 *   - "pem": a certificate file; "pubkey": a public key file
 *   - "jwk": a JWK; "jwks_uri" or "eckey_uri": a URL serving the
 *     verification keys; "aws_alb": an AWS ALB style key URL
 *   - "introspect": a token introspection endpoint URL (RFC 7662)
 *   - "metadata": an authorization server metadata URL (RFC 8414)
 *     from which the verification keys or introspection endpoint are
 *     discovered
 * @param value the key (material), filename or URL, per @p type
 * @param options form-encoded options: claim validation requirements
 *   and expected values ("verify.iss=required&iss=<url>", similarly
 *   "aud", "exp", "nbf", "iat"), the verification result cache
 *   ("verify.cache=<name>&expiry=<seconds>"), the presentation type
 *   ("type=bearer|dpop|mtls") with its "dpop." and "mtls." settings,
 *   and type-specific options such as "kid", "ssl_verify" or the
 *   introspection endpoint/auth parameters
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_token_verify_add_options(oauth2_log_t *log,
					  oauth2_cfg_token_verify_t **verify,
					  const char *type, const char *value,
					  const char *options);
/** @} */

/**
 * @name Token presentation in a request
 * Describes where a token appears in an HTTP request - an environment
 * variable, a header, a query or form POST parameter, a cookie or
 * basic authentication - with per-location settings.
 * @{
 */

typedef struct oauth2_cfg_token_in_envvar_t {
	char *name;
} oauth2_cfg_token_in_envvar_t;

typedef struct oauth2_cfg_token_in_header_t {
	char *name;
	char *type;
} oauth2_cfg_token_in_header_t;

typedef struct oauth2_token_in_query_t {
	char *param_name;
} oauth2_cfg_token_in_query_t;

typedef struct oauth2_cfg_token_in_post_t {
	char *param_name;
} oauth2_cfg_token_in_post_t;

typedef struct oauth2_cfg_token_in_cookie_t {
	char *name;
} oauth2_cfg_token_in_cookie_t;

typedef struct oauth2_cfg_token_in_basic_t {
	// TODO: what will be the username?
	uint8_t dummy;
} oauth2_cfg_token_in_basic_t;

typedef struct oauth2_cfg_token_in_t {
	char value;
	oauth2_cfg_token_in_envvar_t envvar;
	oauth2_cfg_token_in_header_t header;
	oauth2_cfg_token_in_query_t query;
	oauth2_cfg_token_in_post_t post;
	oauth2_cfg_token_in_cookie_t cookie;
	oauth2_cfg_token_in_basic_t basic;
} oauth2_cfg_token_in_t;

typedef enum oauth2_cfg_token_in_type_t {
	// undefined = 0
	OAUTH2_CFG_TOKEN_IN_ENVVAR = 1,
	OAUTH2_CFG_TOKEN_IN_HEADER = 2,
	OAUTH2_CFG_TOKEN_IN_QUERY = 4,
	OAUTH2_CFG_TOKEN_IN_POST = 8,
	OAUTH2_CFG_TOKEN_IN_COOKIE = 16,
	OAUTH2_CFG_TOKEN_IN_BASIC = 32
} oauth2_cfg_token_in_type_t;

#define OAUTH2_CFG_TOKEN_IN_ENVVAR_STR "environment"
#define OAUTH2_CFG_TOKEN_IN_HEADER_STR "header"
#define OAUTH2_CFG_TOKEN_IN_QUERY_STR "query"
#define OAUTH2_CFG_TOKEN_IN_POST_STR "post"
#define OAUTH2_CFG_TOKEN_IN_COOKIE_STR "cookie"
#define OAUTH2_CFG_TOKEN_IN_BASIC_STR "basic"

/**
 * @brief Configure a token location.
 *
 * @param log     the log handle to use
 * @param cfg     the token location configuration to populate
 * @param method  one of the OAUTH2_CFG_TOKEN_IN_..._STR names
 * @param params  location-specific parameters, e.g. the header, cookie
 *                or query/post parameter name
 * @param allowed bitmask of oauth2_cfg_token_in_type_t values
 *                restricting the methods accepted here
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_token_in_set(oauth2_log_t *log, oauth2_cfg_token_in_t *cfg,
			      const char *method,
			      const oauth2_nv_list_t *params,
			      oauth2_uint_t allowed);
/** @} */

/**
 * @name Source token retrieval
 * oauth2_cfg_source_token_t configures where an incoming (source)
 * token is accepted in a request - one or more of the locations above -
 * and whether it is stripped from the request before the request is
 * passed on to the target application. Consumed by
 * oauth2_get_source_token() (proto.h).
 * @{
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, source_token)

char *oauth2_cfg_source_token_set_accept_in(oauth2_log_t *log,
					    oauth2_cfg_source_token_t *cfg,
					    const char *method,
					    const char *options);
/** @brief Return the accepted locations as a bitmask. */
char oauth2_cfg_source_token_get_accept_in(oauth2_cfg_source_token_t *cfg);
oauth2_flag_t oauth2_cfg_source_token_get_strip(oauth2_cfg_source_token_t *cfg);
/** @} */

/**
 * @name Target pass
 * oauth2_cfg_target_pass_t configures how the verified token's claims
 * are passed on to the target application: as headers and/or
 * environment variables, under which name prefix, which claim becomes
 * the remote user, the header carrying the authenticated user, the
 * claim under which the full JSON payload is passed, and the encoding
 * applied to claim values. Options:
 * "headers", "envvars", "prefix", "authn_header", "remote_user_claim",
 * "json_payload_claim", "encoding".
 * @{
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, target_pass)

/**
 * @brief The encoding applied to claim values passed on to the target
 *        application in headers and environment variables.
 */
typedef enum oauth2_cfg_target_pass_encoding_t {
	OAUTH2_CFG_TARGET_PASS_ENCODING_NONE,
	OAUTH2_CFG_TARGET_PASS_ENCODING_LATIN1,
	OAUTH2_CFG_TARGET_PASS_ENCODING_BASE64URL
} oauth2_cfg_target_pass_encoding_t;

char *oauth2_cfg_set_target_pass_options(oauth2_log_t *log,
					 oauth2_cfg_target_pass_t *cfg,
					 const char *options);
oauth2_flag_t
oauth2_cfg_target_pass_get_as_headers(oauth2_cfg_target_pass_t *cfg);
oauth2_flag_t
oauth2_cfg_target_pass_get_as_envvars(oauth2_cfg_target_pass_t *cfg);
const char *oauth2_cfg_target_pass_get_prefix(oauth2_cfg_target_pass_t *cfg);
const char *
oauth2_cfg_target_pass_get_authn_header(oauth2_cfg_target_pass_t *cfg);
const char *
oauth2_cfg_target_get_remote_user_claim(oauth2_cfg_target_pass_t *cfg);
const char *
oauth2_cfg_target_get_json_payload_claim(oauth2_cfg_target_pass_t *cfg);
oauth2_cfg_target_pass_encoding_t
oauth2_cfg_target_pass_get_encoding(oauth2_cfg_target_pass_t *cfg);

/**
 * @brief Apply the configured encoding to a claim value.
 *
 * @return a newly allocated string, to be released with
 *         oauth2_mem_free(), or NULL when @p value is NULL
 */
char *oauth2_cfg_target_pass_encode(oauth2_log_t *log,
				    oauth2_cfg_target_pass_t *cfg,
				    const char *value);
/** @} */

/**
 * @name Resource Owner Password Credentials
 * oauth2_cfg_ropc_t configures the ROPC grant (RFC 6749 section 4.3):
 * the token endpoint (URL plus endpoint/auth options) and the
 * "client_id", "username", "password" and extra request parameters.
 * Executed with oauth2_ropc_exec() (proto.h).
 * @{
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, ropc)

char *oauth2_cfg_set_ropc(oauth2_log_t *log, oauth2_cfg_ropc_t *cfg,
			  const char *url, const char *options);

// TODO: just ropc_exec, no member get functions?

const oauth2_cfg_endpoint_t *
oauth2_cfg_ropc_get_token_endpoint(oauth2_cfg_ropc_t *cfg);
const char *oauth2_cfg_ropc_get_client_id(oauth2_cfg_ropc_t *cfg);
const char *oauth2_cfg_ropc_get_username(oauth2_cfg_ropc_t *cfg);
const char *oauth2_cfg_ropc_get_password(oauth2_cfg_ropc_t *cfg);
const oauth2_nv_list_t *
oauth2_cfg_ropc_get_request_parameters(oauth2_cfg_ropc_t *cfg);
/** @} */

/**
 * @name Client Credentials
 * oauth2_cfg_cc_t configures the Client Credentials grant (RFC 6749
 * section 4.4): the token endpoint (URL plus endpoint/auth options)
 * and extra request parameters. Executed with oauth2_cc_exec()
 * (proto.h).
 * @{
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, cc)

char *oauth2_cfg_set_cc(oauth2_log_t *log, oauth2_cfg_cc_t *cfg,
			const char *url, const char *options);

const oauth2_cfg_endpoint_t *
oauth2_cfg_cc_get_token_endpoint(oauth2_cfg_cc_t *cfg);
const char *oauth2_cfg_cc_get_client_id(oauth2_cfg_cc_t *cfg);
const oauth2_nv_list_t *
oauth2_cfg_cc_get_request_parameters(oauth2_cfg_cc_t *cfg);
/** @} */

#endif /* _OAUTH2_CFG_H_ */
