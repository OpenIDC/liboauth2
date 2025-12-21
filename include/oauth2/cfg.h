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

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "oauth2/util.h"

#define OAUTH2_CFG_FLAG_UNSET (oauth2_flag_t) - 1
#define OAUTH2_CFG_UINT_UNSET (oauth2_uint_t) - 1
#define OAUTH2_CFG_TIME_UNSET (oauth2_time_t) - 1

/*
 * generic
 */

const char *oauth2_cfg_set_flag_slot(void *cfg, size_t offset,
				     const char *value);
const char *oauth2_cfg_set_uint_slot(void *cfg, size_t offset,
				     const char *value);
const char *oauth2_cfg_set_time_slot(void *cfg, size_t offset,
				     const char *value);
const char *oauth2_cfg_set_str_slot(void *cfg, size_t offset,
				    const char *value);

#define OAUTH2_CFG_TYPE_DECLARE(module, object)                                \
	OAUTH2_TYPE_DECLARE(module, object)                                    \
	void oauth2_##module##_##object##_merge(                               \
	    oauth2_log_t *, oauth2_##module##_##object##_t *,                  \
	    oauth2_##module##_##object##_t *,                                  \
	    oauth2_##module##_##object##_t *);

const char *oauth2_crypto_passphrase_set(oauth2_log_t *log, void *dummy,
					 const char *passphrase);
const char *oauth2_crypto_passphrase_get(oauth2_log_t *log);

/*
 * cache
 */

char *oauth2_cfg_set_cache(oauth2_log_t *log, void *dummy, const char *type,
			   const char *options);

/*
 * webserver callbacks
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

/*
 * endpoint auth
 */

/*
 *   <type> <options>
 *
 *   client_secret_basic client_id=<string>&client_secret=<string>
 *   client_secret_post  client_id=<string>&client_secret=<string>
 *   client_secret_jwt   client_id=<string>&client_secret=<string>&aud=<string>
 *   private_key_jwt     jwk=<json>&aud=<string>
 *   client_cert         cert=<filename>&key=<filename>
 *   basic               username=<string>&password=<string>
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

char *oauth2_cfg_set_endpoint_auth(oauth2_log_t *log,
				   oauth2_cfg_endpoint_auth_t *auth,
				   const char *type,
				   const oauth2_nv_list_t *params,
				   const char *prefix);

oauth2_cfg_endpoint_auth_type_t
oauth2_cfg_endpoint_auth_type(const oauth2_cfg_endpoint_auth_t *auth);

/*
 * endpoint
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

/*
 * token verify
 */

typedef enum oauth2_cfg_token_verify_type_t {
	OAUTH2_TOKEN_VERIFY_BEARER,
	OAUTH2_TOKEN_VERIFY_DPOP,
	OAUTH2_TOKEN_VERIFY_MTLS
} oauth2_cfg_token_verify_type_t;

/*
 *   <type> <value> [<options>]
 *
 *   plain|b64|hex   <symmetric-key-string> [kid=<kid>] |
 *   pem             <cert-file> [kid=<kid>] |
 *   pubkey          <public-key-file> [kid=<kid>] |
 *   jwk             <jwk> |
 *   jwks_uri        <url>
 * [type=<restrict-to-keytype>&refresh=<interval>&ssl_verify=<bool>] pubkey_uri
 * <url> [type=<restrict-to-keytype>&refresh=<interval>&ssl_verify=<bool>]
 *
 *   introspect      <url>
 *
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, token_verify)

char *oauth2_cfg_token_verify_add_options(oauth2_log_t *log,
					  oauth2_cfg_token_verify_t **verify,
					  const char *type, const char *value,
					  const char *options);

/*
 * token in request
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

char *oauth2_cfg_token_in_set(oauth2_log_t *log, oauth2_cfg_token_in_t *cfg,
			      const char *method,
			      const oauth2_nv_list_t *params,
			      oauth2_uint_t allowed);

/*
 * source token
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, source_token)

char *oauth2_cfg_source_token_set_accept_in(oauth2_log_t *log,
					    oauth2_cfg_source_token_t *cfg,
					    const char *method,
					    const char *options);
char oauth2_cfg_source_token_get_accept_in(oauth2_cfg_source_token_t *cfg);
oauth2_flag_t oauth2_cfg_source_token_get_strip(oauth2_cfg_source_token_t *cfg);

/*
 * target pass
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, target_pass)

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

/*
 * resource owner password credentials
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

/*
 * client credentials
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, cc)

char *oauth2_cfg_set_cc(oauth2_log_t *log, oauth2_cfg_cc_t *cfg,
			const char *url, const char *options);

const oauth2_cfg_endpoint_t *
oauth2_cfg_cc_get_token_endpoint(oauth2_cfg_cc_t *cfg);
const char *oauth2_cfg_cc_get_client_id(oauth2_cfg_cc_t *cfg);
const oauth2_nv_list_t *
oauth2_cfg_cc_get_request_parameters(oauth2_cfg_cc_t *cfg);

#endif /* _OAUTH2_CFG_H_ */
