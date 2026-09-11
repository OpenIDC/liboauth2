#ifndef _OAUTH2_CFG_H_
#define _OAUTH2_CFG_H_

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
 * @file cfg.h
 * @brief The configuration object model.
 *
 * Per-feature configuration objects populated from directive-style
 * option strings: this is how server bindings translate their native
 * configuration directives (e.g. Apache or NGINX ones) into typed
 * settings for the core library. Option strings are form-encoded
 * name/value parameters ("name1=value1&name2=value2"); setters return
 * NULL on success or a string describing the offending option.
 *
 * The object types are declared with OAUTH2_CFG_TYPE_DECLARE(), which
 * adds a per-directory merge function to the init/clone/free lifecycle
 * of OAUTH2_TYPE_DECLARE() (util.h). A freshly initialized object has
 * every setting at its "unset" sentinel; the accessor functions
 * substitute the documented default for an unset setting, so callers
 * never see the sentinels.
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "oauth2/util.h"

/**
 * @name Sentinel values for unset flag/integer/time settings
 * A setting left at its sentinel has not been configured: the
 * accessor functions substitute the default and the merge functions
 * let an overriding ("add") configuration win over its base only for
 * settings that are not at their sentinel.
 * @{
 */
/** @brief An oauth2_flag_t setting that has not been configured. */
#define OAUTH2_CFG_FLAG_UNSET (oauth2_flag_t) - 1
/** @brief An oauth2_uint_t setting that has not been configured. */
#define OAUTH2_CFG_UINT_UNSET (oauth2_uint_t) - 1
/** @brief An oauth2_time_t setting that has not been configured. */
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

/**
 * @brief Parse a boolean into the oauth2_flag_t member at @p offset
 *        of @p cfg.
 *
 * @param cfg    the configuration struct
 * @param offset the byte offset of the member, e.g. from offsetof()
 * @param value  "true", "on" or "1" for on, "false", "off" or "0" for
 *               off, compared case-insensitively; NULL leaves the
 *               member as it is
 * @return NULL on success, a static error string when @p cfg is NULL
 *         or @p value is none of the above
 */
const char *oauth2_cfg_set_flag_slot(void *cfg, size_t offset,
				     const char *value);

/**
 * @brief Parse a non-negative decimal integer into the oauth2_uint_t
 *        member at @p offset of @p cfg.
 *
 * @param cfg    the configuration struct
 * @param offset the byte offset of the member, e.g. from offsetof()
 * @param value  the decimal representation of the value
 * @return NULL on success, a static error string when @p cfg or
 *         @p value is NULL or @p value is not a plain non-negative
 *         decimal number (no digits, trailing characters, a negative
 *         value or an overflow)
 */
const char *oauth2_cfg_set_uint_slot(void *cfg, size_t offset,
				     const char *value);

/**
 * @brief Parse a non-negative decimal number of seconds into the
 *        oauth2_time_t member at @p offset of @p cfg.
 *
 * Accepts and rejects the same values as oauth2_cfg_set_uint_slot().
 */
const char *oauth2_cfg_set_time_slot(void *cfg, size_t offset,
				     const char *value);

/**
 * @brief Store a copy of @p value in the char * member at @p offset
 *        of @p cfg.
 *
 * A string previously stored in the member is released.
 *
 * @param cfg    the configuration struct
 * @param offset the byte offset of the member, e.g. from offsetof()
 * @param value  the string to copy
 * @return NULL on success, a static error string when @p cfg or
 *         @p value is NULL or the copy failed
 */
const char *oauth2_cfg_set_str_slot(void *cfg, size_t offset,
				    const char *value);

/**
 * @brief Declare a configuration object type.
 *
 * As OAUTH2_TYPE_DECLARE (util.h), additionally generating a
 * `oauth2_<module>_<object>_merge(log, dst, base, add)` function that
 * combines a base and an overriding (add) configuration into a
 * destination, as used for per-directory/location inheritance in
 * server bindings. Not every type implements every generated function;
 * the per-type documentation below says which ones are missing.
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
 *
 * @param log        the log handle to use
 * @param dummy      ignored; present so that the function can serve
 *                   as a directive setter
 * @param passphrase the passphrase, copied; a previously set one is
 *                   released
 * @return NULL
 */
const char *oauth2_crypto_passphrase_set(oauth2_log_t *log, void *dummy,
					 const char *passphrase);

/**
 * @brief Get the global crypto passphrase.
 *
 * When none was configured a random one of 12 hexadecimal characters
 * is generated, set and logged as a warning: it neither survives a
 * restart nor matches other processes, so configure one explicitly
 * wherever encrypted data has to outlive a single process.
 *
 * @param log the log handle to use
 * @return a borrowed pointer to the passphrase
 */
const char *oauth2_crypto_passphrase_get(oauth2_log_t *log);
/** @} */

/**
 * @brief Create and register a named cache instance.
 *
 * The instance is created, post-configured and registered under its
 * name in one go, so it can be retrieved right away.
 *
 * @param log     the log handle to use
 * @param dummy   ignored
 * @param type    cache backend: "shm" or "file", plus "memcache" and
 *                "redis" when compiled in; NULL selects "shm"
 * @param options form-encoded parameters: "name" to register the
 *                instance under (for retrieval with
 *                oauth2_cache_obtain(), see cache.h), "encrypt"
 *                (whether values are encrypted, defaulting per
 *                backend), "key_hash_algo" and "passphrase_hash_algo"
 *                (OpenSSL digest names for hashing keys and deriving
 *                the encryption key), plus backend-specific settings:
 *                "max_entries", "max_key_size" and "max_val_size" for
 *                "shm", "dir" and "clean_interval" for "file",
 *                "config_string" for "memcache" and "host", "port",
 *                "username" and "password" for "redis"
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_cache(oauth2_log_t *log, void *dummy, const char *type,
			   const char *options);

/**
 * @name Webserver callbacks
 * Callbacks that a server binding provides so the core library can
 * read and set environment variables and read form POST data through
 * the hosting server; the "environment" and "post" token locations of
 * oauth2_get_source_token() (proto.h) use them. The Apache binding
 * provides oauth2_apache_server_callback_funcs (apache.h).
 * @{
 */

/**
 * @brief Read an environment variable of the current request.
 *
 * @param log   the log handle to use
 * @param ctx   the binding's request context, as passed by the caller
 *              that invokes the callbacks
 * @param key   the name of the variable
 * @param value set to its value as a newly allocated string, to be
 *              released with oauth2_mem_free(), or to NULL when the
 *              variable is not set
 * @return true on success, false on error
 */
typedef bool(oauth2_cfg_env_get_cb)(oauth2_log_t *log, void *ctx,
				    const char *key, char **value);

/**
 * @brief Set an environment variable of the current request, or clear
 *        it when @p value is NULL.
 *
 * @param log   the log handle to use
 * @param ctx   the binding's request context
 * @param key   the name of the variable
 * @param value the value to set, NULL to clear the variable
 * @return true on success, false on error
 */
typedef bool(oauth2_cfg_env_set_cb)(oauth2_log_t *log, void *ctx,
				    const char *key, const char *value);

/**
 * @brief Read the body of a form-encoded POST request.
 *
 * @param log    the log handle to use
 * @param ctx    the binding's request context
 * @param params set to the parsed parameters as a new list, to be
 *               released with oauth2_nv_list_free()
 * @return true on success, false when the body could not be read or
 *         parsed
 */
typedef bool(oauth2_cfg_form_post_read_cb)(oauth2_log_t *log, void *ctx,
					   oauth2_nv_list_t **params);

/** @brief The set of callbacks a server binding provides. */
typedef struct oauth2_cfg_server_callback_funcs_t {
	oauth2_cfg_env_get_cb *get; /**< read an environment variable */
	oauth2_cfg_env_set_cb *set; /**< set an environment variable */
	oauth2_cfg_form_post_read_cb *form_post; /**< read POST form data */
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
 private_key_jwt     client_id=<string>&jwk=<json>&aud=<string>
 client_cert         cert=<filename>&key=<filename>
 basic               username=<string>&password=<string>
 @endverbatim
 * @{
 */

/** @brief The client authentication methods. */
typedef enum oauth2_cfg_endpoint_auth_type_t {
	/** No client authentication ("none"), the default. */
	OAUTH2_ENDPOINT_AUTH_NONE,
	/**
	 * client_id and client_secret in an HTTP Basic Authorization
	 * header (RFC 6749 section 2.3.1).
	 */
	OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC,
	/** client_id and client_secret as form parameters. */
	OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST,
	/**
	 * A JWT client assertion (RFC 7523) signed with HS256 using the
	 * client_secret, with the "aud" parameter as its audience.
	 */
	OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT,
	/**
	 * A JWT client assertion (RFC 7523) signed with RS256 using the
	 * private key in the "jwk" parameter, with the "aud" parameter as
	 * its audience.
	 */
	OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT,
	/** A TLS client certificate and key from PEM files (RFC 8705). */
	OAUTH2_ENDPOINT_AUTH_CLIENT_CERT,
	/** HTTP Basic authentication with an arbitrary username/password. */
	OAUTH2_ENDPOINT_AUTH_BASIC
} oauth2_cfg_endpoint_auth_type_t;

/**
 * @brief Opaque endpoint authentication settings.
 *
 * A new object has type OAUTH2_ENDPOINT_AUTH_NONE; the clone copies
 * the credentials of the configured type. The merge function the
 * declaration macro names is not implemented.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, endpoint_auth)
/**
 * @fn oauth2_cfg_endpoint_auth_init(oauth2_log_t *)
 * @brief Allocate a new oauth2_cfg_endpoint_auth_t with its defaults applied;
 *        NULL on allocation failure.
 */
/**
 * @fn oauth2_cfg_endpoint_auth_clone(oauth2_log_t *,
 *     const oauth2_cfg_endpoint_auth_t *)
 * @brief Deep-copy an oauth2_cfg_endpoint_auth_t; release the copy with
 *        oauth2_cfg_endpoint_auth_free().
 */
/**
 * @fn oauth2_cfg_endpoint_auth_free(oauth2_log_t *,
 *     oauth2_cfg_endpoint_auth_t *)
 * @brief Release an oauth2_cfg_endpoint_auth_t and everything it owns; NULL is
 *        ignored.
 */
/**
 * @fn oauth2_cfg_endpoint_auth_merge(oauth2_log_t *,
 *     oauth2_cfg_endpoint_auth_t *, oauth2_cfg_endpoint_auth_t *,
 *     oauth2_cfg_endpoint_auth_t *)
 * @brief Declared by the object macro but not implemented.
 */

/**
 * @brief Configure an endpoint authentication method.
 *
 * @param log    the log handle to use
 * @param auth   the endpoint authentication configuration to populate
 * @param type   one of the method names listed above, or "none"; NULL
 *               leaves @p auth untouched
 * @param params the method-specific parameters listed above, looked up
 *               under their plain names; a missing required parameter
 *               is an error
 * @param prefix currently unused: the parameters are looked up without
 *               a prefix, also when the method is selected through a
 *               prefixed option such as "introspect.auth"
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_endpoint_auth(oauth2_log_t *log,
				   oauth2_cfg_endpoint_auth_t *auth,
				   const char *type,
				   const oauth2_nv_list_t *params,
				   const char *prefix);

/**
 * @brief Get the configured authentication method.
 * @return the method, OAUTH2_ENDPOINT_AUTH_NONE when @p auth is NULL
 */
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

/**
 * @brief Opaque remote endpoint settings.
 *
 * A new object has no URL or authentication settings and every other
 * setting unset; the clone is a deep copy. The merge function the
 * declaration macro names is not implemented.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, endpoint)
/**
 * @fn oauth2_cfg_endpoint_init(oauth2_log_t *)
 * @brief Allocate a new oauth2_cfg_endpoint_t with its defaults applied; NULL
 *        on allocation failure.
 */
/**
 * @fn oauth2_cfg_endpoint_clone(oauth2_log_t *, const oauth2_cfg_endpoint_t *)
 * @brief Deep-copy an oauth2_cfg_endpoint_t; release the copy with
 *        oauth2_cfg_endpoint_free().
 */
/**
 * @fn oauth2_cfg_endpoint_free(oauth2_log_t *, oauth2_cfg_endpoint_t *)
 * @brief Release an oauth2_cfg_endpoint_t and everything it owns; NULL is
 *        ignored.
 */
/**
 * @fn oauth2_cfg_endpoint_merge(oauth2_log_t *, oauth2_cfg_endpoint_t *,
 *     oauth2_cfg_endpoint_t *, oauth2_cfg_endpoint_t *)
 * @brief Declared by the object macro but not implemented.
 */

/**
 * @brief Configure an endpoint from a URL and a set of parameters.
 *
 * The parameters are looked up under a name prefixed with @p prefix
 * and a dot when a prefix is given, e.g. "introspect.ssl_verify", and
 * under their plain name otherwise:
 * - "url": the endpoint URL, when @p url is NULL
 * - "auth": the client authentication method, configured with
 *   oauth2_cfg_set_endpoint_auth() from the same parameters (which
 *   are looked up without the prefix); "none" when absent
 * - "ssl_verify": whether to verify the server's TLS certificate,
 *   default on
 * - "http_timeout": the HTTP timeout in seconds, default 20
 * - "http_retries": how often a failed call is retried, default 1
 * - "http_retry_interval": the interval between retries in
 *   milliseconds, default 300
 * - "outgoing_proxy": the proxy to route the call through, none by
 *   default
 *
 * @param log    the log handle to use
 * @param cfg    the endpoint configuration to populate
 * @param url    the endpoint URL, or NULL to take it from the "url"
 *               parameter
 * @param params the parameters, may be NULL
 * @param prefix the parameter name prefix, may be NULL
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_endpoint(oauth2_log_t *log, oauth2_cfg_endpoint_t *cfg,
			      const char *url, const oauth2_nv_list_t *params,
			      const char *prefix);

/** @brief Get the endpoint URL; NULL when not configured. */
const char *oauth2_cfg_endpoint_get_url(const oauth2_cfg_endpoint_t *cfg);
/** @brief Set the endpoint URL to a copy of @p url, replacing any. */
void oauth2_cfg_endpoint_set_url(oauth2_cfg_endpoint_t *cfg, const char *url);
/**
 * @brief Get the client authentication settings.
 * @return a borrowed pointer, NULL before oauth2_cfg_set_endpoint()
 *         was called
 */
const oauth2_cfg_endpoint_auth_t *
oauth2_cfg_endpoint_get_auth(const oauth2_cfg_endpoint_t *cfg);
/** @brief Whether to verify the server certificate; default on. */
oauth2_flag_t
oauth2_cfg_endpoint_get_ssl_verify(const oauth2_cfg_endpoint_t *cfg);
/** @brief The HTTP timeout in seconds; default 20. */
oauth2_uint_t
oauth2_cfg_endpoint_get_http_timeout(const oauth2_cfg_endpoint_t *cfg);
/** @brief The number of retries of a failed call; default 1. */
oauth2_uint_t
oauth2_cfg_endpoint_get_http_retries(const oauth2_cfg_endpoint_t *cfg);
/** @brief The interval between retries in milliseconds; default 300. */
oauth2_uint_t
oauth2_cfg_endpoint_get_http_retry_interval(const oauth2_cfg_endpoint_t *cfg);
/** @brief The outgoing proxy; NULL when none is configured. */
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
	OAUTH2_TOKEN_VERIFY_BEARER, /**< "bearer", the default */
	OAUTH2_TOKEN_VERIFY_DPOP,   /**< "dpop" */
	OAUTH2_TOKEN_VERIFY_MTLS    /**< "mtls" */
} oauth2_cfg_token_verify_type_t;

/**
 * @brief Opaque chain of token verification methods.
 *
 * Every element holds one method with its own result cache and
 * proof-of-possession settings; the chain is grown with
 * oauth2_cfg_token_verify_add_options() and freed and cloned as a
 * whole. The merge function the declaration macro names is not
 * implemented.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, token_verify)
/**
 * @fn oauth2_cfg_token_verify_init(oauth2_log_t *)
 * @brief Allocate a new oauth2_cfg_token_verify_t with its defaults applied;
 *        NULL on allocation failure.
 */
/**
 * @fn oauth2_cfg_token_verify_clone(oauth2_log_t *,
 *     const oauth2_cfg_token_verify_t *)
 * @brief Deep-copy an oauth2_cfg_token_verify_t; release the copy with
 *        oauth2_cfg_token_verify_free().
 */
/**
 * @fn oauth2_cfg_token_verify_free(oauth2_log_t *, oauth2_cfg_token_verify_t *)
 * @brief Release an oauth2_cfg_token_verify_t and everything it owns; NULL is
 *        ignored.
 */
/**
 * @fn oauth2_cfg_token_verify_merge(oauth2_log_t *,
 *     oauth2_cfg_token_verify_t *, oauth2_cfg_token_verify_t *,
 *     oauth2_cfg_token_verify_t *)
 * @brief Declared by the object macro but not implemented.
 */

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
 *     verification keys; "aws_alb": the ARN of an AWS ALB whose keys
 *     are fetched from its region's key endpoint
 *   - "introspect": a token introspection endpoint URL (RFC 7662)
 *   - "metadata": an authorization server metadata URL (RFC 8414)
 *     from which the verification keys or introspection endpoint are
 *     discovered
 * @param value the key (material), filename, URL or ARN, per @p type
 * @param options form-encoded options:
 *   - for the JWT types, the expected "iss" and "aud" values and how
 *     strictly each claim is validated, "required", "optional" or
 *     "skip": "verify.iss" and "verify.aud" (required once an expected
 *     value is configured, otherwise not checked), "verify.exp"
 *     (required, except for "eckey_uri" and "aws_alb" tokens that
 *     carry it in the header), "verify.nbf" and "verify.iat"
 *     (optional), with "verify.iat.slack_before" (none by default)
 *     and "verify.iat.slack_after" (10 seconds) for the "iat" check;
 *     "kid" overrides the key identifier of a single key
 *   - endpoint settings (see oauth2_cfg_set_endpoint()) prefixed with
 *     the type name for the "introspect", "jwks_uri", "eckey_uri" and
 *     "metadata" types, e.g. "introspect.auth" or
 *     "jwks_uri.ssl_verify", plus the "<type>.cache" and "<type>.expiry"
 *     (default 86400 seconds) settings for caching what the URL serves
 *     ("metadata" takes both "metadata." and "jwks_uri." settings),
 *     "introspect.token_param_name" (default "token") and
 *     "introspect.params" for extra introspection request parameters,
 *     and "alb_base_url" for "aws_alb"
 *   - the verification result cache: "verify.cache" (a cache name,
 *     the default cache when absent) and "expiry" (300 seconds)
 *   - the presentation type "type=bearer|dpop|mtls" with, for DPoP,
 *     the proof replay cache "dpop.cache" and "dpop.expiry" (10
 *     seconds), "dpop.iat.verify" (required), "dpop.iat.slack.before"
 *     and "dpop.iat.slack.after" (5 seconds), and for mTLS
 *     "mtls.env_var_name" (the variable carrying the client
 *     certificate) and "mtls.policy" ("optional" or "required")
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
 * basic authentication - with per-location settings. The defaults
 * mentioned below are applied by oauth2_get_source_token() (proto.h).
 * @{
 */

/** @brief The "environment" location. */
typedef struct oauth2_cfg_token_in_envvar_t {
	/** The environment variable name; default "access_token". */
	char *name;
} oauth2_cfg_token_in_envvar_t;

/** @brief The "header" location. */
typedef struct oauth2_cfg_token_in_header_t {
	/** The header name; default "Authorization". */
	char *name;
	/**
	 * The scheme the header value must start with; default "bearer",
	 * an empty string accepts the whole header value.
	 */
	char *type;
} oauth2_cfg_token_in_header_t;

/** @brief The "query" location. */
typedef struct oauth2_token_in_query_t {
	/** The query parameter name; default "access_token". */
	char *param_name;
} oauth2_cfg_token_in_query_t;

/** @brief The "post" location. */
typedef struct oauth2_cfg_token_in_post_t {
	/** The form POST parameter name; default "access_token". */
	char *param_name;
} oauth2_cfg_token_in_post_t;

/** @brief The "cookie" location. */
typedef struct oauth2_cfg_token_in_cookie_t {
	/** The cookie name; default "access_token". */
	char *name;
} oauth2_cfg_token_in_cookie_t;

/** @brief The "basic" location, which has no settings. */
typedef struct oauth2_cfg_token_in_basic_t {
	// TODO: what will be the username?
	uint8_t dummy; /**< placeholder, unused */
} oauth2_cfg_token_in_basic_t;

/** @brief The enabled locations and their settings. */
typedef struct oauth2_cfg_token_in_t {
	/** Bitmask of oauth2_cfg_token_in_type_t values; 0 when unset. */
	char value;
	oauth2_cfg_token_in_envvar_t envvar; /**< "environment" settings */
	oauth2_cfg_token_in_header_t header; /**< "header" settings */
	oauth2_cfg_token_in_query_t query;   /**< "query" settings */
	oauth2_cfg_token_in_post_t post;     /**< "post" settings */
	oauth2_cfg_token_in_cookie_t cookie; /**< "cookie" settings */
	oauth2_cfg_token_in_basic_t basic;   /**< "basic" settings */
} oauth2_cfg_token_in_t;

/** @brief The token locations, as bit flags. */
typedef enum oauth2_cfg_token_in_type_t {
	// undefined = 0
	OAUTH2_CFG_TOKEN_IN_ENVVAR = 1,	 /**< an environment variable */
	OAUTH2_CFG_TOKEN_IN_HEADER = 2,	 /**< a header */
	OAUTH2_CFG_TOKEN_IN_QUERY = 4,	 /**< a query parameter */
	OAUTH2_CFG_TOKEN_IN_POST = 8,	 /**< a form POST parameter */
	OAUTH2_CFG_TOKEN_IN_COOKIE = 16, /**< a cookie */
	OAUTH2_CFG_TOKEN_IN_BASIC = 32	 /**< basic authentication */
} oauth2_cfg_token_in_type_t;

/** @brief The name of the OAUTH2_CFG_TOKEN_IN_ENVVAR location. */
#define OAUTH2_CFG_TOKEN_IN_ENVVAR_STR "environment"
/** @brief The name of the OAUTH2_CFG_TOKEN_IN_HEADER location. */
#define OAUTH2_CFG_TOKEN_IN_HEADER_STR "header"
/** @brief The name of the OAUTH2_CFG_TOKEN_IN_QUERY location. */
#define OAUTH2_CFG_TOKEN_IN_QUERY_STR "query"
/** @brief The name of the OAUTH2_CFG_TOKEN_IN_POST location. */
#define OAUTH2_CFG_TOKEN_IN_POST_STR "post"
/** @brief The name of the OAUTH2_CFG_TOKEN_IN_COOKIE location. */
#define OAUTH2_CFG_TOKEN_IN_COOKIE_STR "cookie"
/** @brief The name of the OAUTH2_CFG_TOKEN_IN_BASIC location. */
#define OAUTH2_CFG_TOKEN_IN_BASIC_STR "basic"

/**
 * @brief Enable a token location.
 *
 * Adds the location to the ones already enabled in @p cfg and stores
 * its settings, so calling this once per location enables several.
 *
 * @param log     the log handle to use
 * @param cfg     the token location configuration to populate
 * @param method  one of the OAUTH2_CFG_TOKEN_IN_..._STR names
 * @param params  location-specific parameters: "name" sets the
 *                variable, header, parameter or cookie name of the
 *                location and "type" the scheme of the "header"
 *                location; "basic" has none
 * @param allowed bitmask of oauth2_cfg_token_in_type_t values
 *                restricting the methods accepted here
 * @return NULL on success, an error string when @p method is NULL,
 *         unknown or not in @p allowed
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

/**
 * @brief Opaque source token settings.
 *
 * A new object has no location enabled and the strip flag unset. The
 * merge takes the "add" configuration as a whole when it has any
 * location enabled and the "base" one otherwise.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, source_token)
/**
 * @fn oauth2_cfg_source_token_init(oauth2_log_t *)
 * @brief Allocate a new oauth2_cfg_source_token_t with its defaults applied;
 *        NULL on allocation failure.
 */
/**
 * @fn oauth2_cfg_source_token_clone(oauth2_log_t *,
 *     const oauth2_cfg_source_token_t *)
 * @brief Deep-copy an oauth2_cfg_source_token_t; release the copy with
 *        oauth2_cfg_source_token_free().
 */
/**
 * @fn oauth2_cfg_source_token_free(oauth2_log_t *, oauth2_cfg_source_token_t *)
 * @brief Release an oauth2_cfg_source_token_t and everything it owns; NULL is
 *        ignored.
 */
/**
 * @fn oauth2_cfg_source_token_merge(oauth2_log_t *,
 *     oauth2_cfg_source_token_t *, oauth2_cfg_source_token_t *,
 *     oauth2_cfg_source_token_t *)
 * @brief Merge two oauth2_cfg_source_token_t objects into a third: a value set
 *        in add takes precedence over base.
 */

/**
 * @brief Enable a location the token is accepted in.
 *
 * @param log     the log handle to use
 * @param cfg     the source token configuration to populate
 * @param method  one of the OAUTH2_CFG_TOKEN_IN_..._STR names; every
 *                location is allowed
 * @param options form-encoded parameters: the location's own ones (see
 *                oauth2_cfg_token_in_set()) plus "strip" (a boolean)
 *                setting the strip flag
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_source_token_set_accept_in(oauth2_log_t *log,
					    oauth2_cfg_source_token_t *cfg,
					    const char *method,
					    const char *options);
/**
 * @brief Return the accepted locations as a bitmask.
 * @return the enabled oauth2_cfg_token_in_type_t values; the
 *         environment variable and the header when none was enabled
 */
char oauth2_cfg_source_token_get_accept_in(oauth2_cfg_source_token_t *cfg);
/**
 * @brief Whether the token is stripped from the location it was taken
 *        from; default on.
 */
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

/**
 * @brief Opaque target pass settings.
 *
 * A new object has every setting unset. The merge takes each setting
 * from the "add" configuration when set there and from the "base" one
 * otherwise. The clone function the declaration macro names is not
 * implemented.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, target_pass)
/**
 * @fn oauth2_cfg_target_pass_init(oauth2_log_t *)
 * @brief Allocate a new oauth2_cfg_target_pass_t with its defaults applied;
 *        NULL on allocation failure.
 */
/**
 * @fn oauth2_cfg_target_pass_clone(oauth2_log_t *,
 *     const oauth2_cfg_target_pass_t *)
 * @brief Declared by the object macro but not implemented; an
 *        oauth2_cfg_target_pass_t cannot be copied.
 */
/**
 * @fn oauth2_cfg_target_pass_free(oauth2_log_t *, oauth2_cfg_target_pass_t *)
 * @brief Release an oauth2_cfg_target_pass_t and everything it owns; NULL is
 *        ignored.
 */
/**
 * @fn oauth2_cfg_target_pass_merge(oauth2_log_t *, oauth2_cfg_target_pass_t *,
 *     oauth2_cfg_target_pass_t *, oauth2_cfg_target_pass_t *)
 * @brief Merge two oauth2_cfg_target_pass_t objects into a third: a value set
 *        in add takes precedence over base.
 */

/**
 * @brief The encoding applied to claim values passed on to the target
 *        application in headers and environment variables.
 */
typedef enum oauth2_cfg_target_pass_encoding_t {
	/** "none": the value as it is. */
	OAUTH2_CFG_TARGET_PASS_ENCODING_NONE,
	/**
	 * "latin1": the UTF-8 value converted to ISO-8859-1, characters
	 * outside of it becoming "?"; the default.
	 */
	OAUTH2_CFG_TARGET_PASS_ENCODING_LATIN1,
	/** "base64url": the value base64url-encoded. */
	OAUTH2_CFG_TARGET_PASS_ENCODING_BASE64URL
} oauth2_cfg_target_pass_encoding_t;

/**
 * @brief Configure the target pass settings from an option string.
 *
 * @param log     the log handle to use
 * @param cfg     the target pass configuration to populate
 * @param options form-encoded parameters: "headers" and "envvars"
 *                (booleans, both default on), "prefix" (default
 *                "OAUTH2_CLAIM_"), "authn_header" (no default),
 *                "remote_user_claim" (default "sub"),
 *                "json_payload_claim" (no default) and "encoding"
 *                ("latin1", "base64url" or "none", default "latin1")
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_target_pass_options(oauth2_log_t *log,
					 oauth2_cfg_target_pass_t *cfg,
					 const char *options);
/** @brief Whether claims are passed as headers; default on. */
oauth2_flag_t
oauth2_cfg_target_pass_get_as_headers(oauth2_cfg_target_pass_t *cfg);
/** @brief Whether claims are passed as environment variables; on. */
oauth2_flag_t
oauth2_cfg_target_pass_get_as_envvars(oauth2_cfg_target_pass_t *cfg);
/**
 * @brief The prefix of the header and environment variable names;
 *        default "OAUTH2_CLAIM_".
 */
const char *oauth2_cfg_target_pass_get_prefix(oauth2_cfg_target_pass_t *cfg);
/**
 * @brief The header carrying the authenticated user; NULL when none
 *        is configured.
 */
const char *
oauth2_cfg_target_pass_get_authn_header(oauth2_cfg_target_pass_t *cfg);
/** @brief The claim that becomes the remote user; default "sub". */
const char *
oauth2_cfg_target_get_remote_user_claim(oauth2_cfg_target_pass_t *cfg);
/**
 * @brief The name under which the full JSON payload is passed; NULL
 *        when it is not passed.
 */
const char *
oauth2_cfg_target_get_json_payload_claim(oauth2_cfg_target_pass_t *cfg);
/** @brief The encoding applied to claim values; default latin1. */
oauth2_cfg_target_pass_encoding_t
oauth2_cfg_target_pass_get_encoding(oauth2_cfg_target_pass_t *cfg);

/**
 * @brief Apply the configured encoding to a claim value.
 *
 * @param log   the log handle to use
 * @param cfg   the target pass configuration
 * @param value the value to encode
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

/**
 * @brief Opaque ROPC grant settings.
 *
 * A new object has no token endpoint or other settings. The merge
 * takes the "add" configuration as a whole when it has a token
 * endpoint and the "base" one otherwise.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, ropc)
/**
 * @fn oauth2_cfg_ropc_init(oauth2_log_t *)
 * @brief Allocate a new oauth2_cfg_ropc_t with its defaults applied; NULL on
 *        allocation failure.
 */
/**
 * @fn oauth2_cfg_ropc_clone(oauth2_log_t *, const oauth2_cfg_ropc_t *)
 * @brief Deep-copy an oauth2_cfg_ropc_t; release the copy with
 *        oauth2_cfg_ropc_free().
 */
/**
 * @fn oauth2_cfg_ropc_free(oauth2_log_t *, oauth2_cfg_ropc_t *)
 * @brief Release an oauth2_cfg_ropc_t and everything it owns; NULL is ignored.
 */
/**
 * @fn oauth2_cfg_ropc_merge(oauth2_log_t *, oauth2_cfg_ropc_t *,
 *     oauth2_cfg_ropc_t *, oauth2_cfg_ropc_t *)
 * @brief Merge two oauth2_cfg_ropc_t objects into a third: a value set in add
 *        takes precedence over base.
 */

/**
 * @brief Configure the ROPC grant from a token endpoint URL and an
 *        option string.
 *
 * @param log     the log handle to use
 * @param cfg     the ROPC configuration to populate
 * @param url     the token endpoint URL, or NULL to take it from the
 *                "url" option
 * @param options form-encoded parameters: the unprefixed endpoint
 *                settings of oauth2_cfg_set_endpoint() ("auth",
 *                "ssl_verify", "http_timeout", ...), "client_id"
 *                (sent as a parameter when the endpoint
 *                authentication method is "none"), "username" and
 *                "password", and "params" (a form-encoded string of
 *                extra parameters to send in the token request, e.g.
 *                "scope=openid")
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_ropc(oauth2_log_t *log, oauth2_cfg_ropc_t *cfg,
			  const char *url, const char *options);

// TODO: just ropc_exec, no member get functions?

/**
 * @brief The token endpoint; NULL before oauth2_cfg_set_ropc() was
 *        called.
 */
const oauth2_cfg_endpoint_t *
oauth2_cfg_ropc_get_token_endpoint(oauth2_cfg_ropc_t *cfg);
/** @brief The client_id; NULL when not configured. */
const char *oauth2_cfg_ropc_get_client_id(oauth2_cfg_ropc_t *cfg);
/**
 * @brief The configured username; NULL when not configured. Not used
 *        by oauth2_ropc_exec(), which takes the username as an
 *        argument.
 */
const char *oauth2_cfg_ropc_get_username(oauth2_cfg_ropc_t *cfg);
/**
 * @brief The configured password; NULL when not configured. Not used
 *        by oauth2_ropc_exec(), which takes the password as an
 *        argument.
 */
const char *oauth2_cfg_ropc_get_password(oauth2_cfg_ropc_t *cfg);
/**
 * @brief The extra token request parameters; NULL when none are
 *        configured.
 */
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

/**
 * @brief Opaque Client Credentials grant settings.
 *
 * A new object has no token endpoint or other settings. The merge
 * takes the "add" configuration as a whole when it has a token
 * endpoint and the "base" one otherwise.
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, cc)
/**
 * @fn oauth2_cfg_cc_init(oauth2_log_t *)
 * @brief Allocate a new oauth2_cfg_cc_t with its defaults applied; NULL on
 *        allocation failure.
 */
/**
 * @fn oauth2_cfg_cc_clone(oauth2_log_t *, const oauth2_cfg_cc_t *)
 * @brief Deep-copy an oauth2_cfg_cc_t; release the copy with
 *        oauth2_cfg_cc_free().
 */
/**
 * @fn oauth2_cfg_cc_free(oauth2_log_t *, oauth2_cfg_cc_t *)
 * @brief Release an oauth2_cfg_cc_t and everything it owns; NULL is ignored.
 */
/**
 * @fn oauth2_cfg_cc_merge(oauth2_log_t *, oauth2_cfg_cc_t *, oauth2_cfg_cc_t *,
 *     oauth2_cfg_cc_t *)
 * @brief Merge two oauth2_cfg_cc_t objects into a third: a value set in add
 *        takes precedence over base.
 */

/**
 * @brief Configure the Client Credentials grant from a token endpoint
 *        URL and an option string.
 *
 * @param log     the log handle to use
 * @param cfg     the Client Credentials configuration to populate
 * @param url     the token endpoint URL, or NULL to take it from the
 *                "url" option
 * @param options form-encoded parameters: the unprefixed endpoint
 *                settings of oauth2_cfg_set_endpoint() ("auth",
 *                "ssl_verify", "http_timeout", ...), "client_id" (sent
 *                as a parameter when the endpoint authentication
 *                method is "none") and "params" (a form-encoded string
 *                of extra parameters to send in the token request)
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_set_cc(oauth2_log_t *log, oauth2_cfg_cc_t *cfg,
			const char *url, const char *options);

/**
 * @brief The token endpoint; NULL before oauth2_cfg_set_cc() was
 *        called.
 */
const oauth2_cfg_endpoint_t *
oauth2_cfg_cc_get_token_endpoint(oauth2_cfg_cc_t *cfg);
/** @brief The client_id; NULL when not configured. */
const char *oauth2_cfg_cc_get_client_id(oauth2_cfg_cc_t *cfg);
/**
 * @brief The extra token request parameters; NULL when none are
 *        configured.
 */
const oauth2_nv_list_t *
oauth2_cfg_cc_get_request_parameters(oauth2_cfg_cc_t *cfg);
/** @} */

#endif /* _OAUTH2_CFG_H_ */
