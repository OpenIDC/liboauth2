#ifndef _OAUTH2_CFG_INT_H_
#define _OAUTH2_CFG_INT_H_

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

#include "oauth2/cache.h"
#include "oauth2/cfg.h"
#include "oauth2/oauth2.h"
#include "oauth2/openidc.h"
#include "oauth2/session.h"

#include <cjose/cjose.h>

typedef enum oauth2_jose_jwt_validate_claim_t {
	OAUTH2_JOSE_JWT_VALIDATE_CLAIM_OPTIONAL,
	OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED,
	OAUTH2_JOSE_JWT_VALIDATE_CLAIM_SKIP
} oauth2_jose_jwt_validate_claim_t;

oauth2_jose_jwt_validate_claim_t oauth2_parse_validate_claim_option(
    oauth2_log_t *log, const char *value,
    oauth2_jose_jwt_validate_claim_t default_value);

/*
 * endpoint
 */

typedef struct oauth2_cfg_endpoint_t {
	char *url;
	oauth2_cfg_endpoint_auth_t *auth;
	oauth2_flag_t ssl_verify;
	oauth2_uint_t http_timeout;
	char *outgoing_proxy;
} oauth2_cfg_endpoint_t;

/*
 * auth
 */

typedef struct oauth2_cfg_endpoint_auth_none_t {
	uint8_t dummy;
} oauth2_cfg_endpoint_auth_none_t;

typedef struct oauth2_cfg_endpoint_auth_client_secret_basic_t {
	char *client_id;
	char *client_secret;
} oauth2_cfg_endpoint_auth_client_secret_basic_t;

typedef struct oauth2_cfg_endpoint_auth_client_secret_post_t {
	char *client_id;
	char *client_secret;
} oauth2_cfg_endpoint_auth_client_secret_post_t;

typedef struct oauth2_cfg_endpoint_auth_client_secret_jwt_t {
	char *client_id;
	cjose_jwk_t *jwk;
	char *aud;
} oauth2_cfg_endpoint_auth_client_secret_jwt_t;

typedef struct oauth2_cfg_endpoint_auth_private_key_jwt_t {
	char *client_id;
	cjose_jwk_t *jwk;
	char *aud;
} oauth2_cfg_endpoint_auth_private_key_jwt_t;

typedef struct oauth2_cfg_endpoint_auth_client_cert_t {
	char *certfile;
	char *keyfile;
} oauth2_cfg_endpoint_auth_client_cert_t;

typedef struct oauth2_cfg_endpoint_auth_basic_t {
	char *username;
	char *password;
} oauth2_cfg_endpoint_auth_basic_t;

typedef struct oauth2_cfg_endpoint_auth_t {
	oauth2_cfg_endpoint_auth_type_t type;
	union {
		oauth2_cfg_endpoint_auth_none_t none;
		oauth2_cfg_endpoint_auth_client_secret_basic_t
		    client_secret_basic;
		oauth2_cfg_endpoint_auth_client_secret_post_t
		    client_secret_post;
		oauth2_cfg_endpoint_auth_client_secret_jwt_t client_secret_jwt;
		oauth2_cfg_endpoint_auth_private_key_jwt_t private_key_jwt;
		oauth2_cfg_endpoint_auth_client_cert_t client_cert;
		oauth2_cfg_endpoint_auth_basic_t basic;
	};
} oauth2_cfg_endpoint_auth_t;

/*
 * source token
 */

typedef struct oauth2_cfg_source_token_t {
	oauth2_cfg_token_in_t accept_in;
	oauth2_flag_t strip;
} oauth2_cfg_source_token_t;

/*
 * cache
 */

// typedef struct oauth2_cfg_cache_t {
//	oauth2_cache_t *cache;
//	oauth2_time_t expiry_s;
//} oauth2_cfg_cache_t;
//
// oauth2_cfg_cache_t *oauth2_cfg_cache_init(oauth2_log_t *log);
// oauth2_cfg_cache_t *oauth2_cfg_cache_clone(oauth2_log_t *log,
//					   oauth2_cfg_cache_t *src);
// void oauth2_cfg_cache_free(oauth2_log_t *log, oauth2_cfg_cache_t *cache);

char *oauth2_cfg_cache_set_options(oauth2_log_t *log, const char *type,
				   const oauth2_nv_list_t *params);

/*
 * verify
 */

typedef void *(oauth2_cfg_ctx_init_cb)(oauth2_log_t *log);
typedef void *(oauth2_cfg_ctx_clone_cb)(oauth2_log_t *log, void *src);
typedef void(oauth2_cfg_ctx_free_cb)(oauth2_log_t *log, void *);

typedef struct oauth2_cfg_ctx_funcs_t {
	oauth2_cfg_ctx_init_cb *init;
	oauth2_cfg_ctx_clone_cb *clone;
	oauth2_cfg_ctx_free_cb *free;
} oauth2_cfg_ctx_funcs_t;

typedef bool(oauth2_cfg_token_verify_cb_t)(oauth2_log_t *,
					   oauth2_cfg_token_verify_t *,
					   const char *, json_t **,
					   char **s_payload);

typedef struct oauth2_cfg_ctx_t {
	void *ptr;
	oauth2_cfg_ctx_funcs_t *callbacks;
} oauth2_cfg_ctx_t;

oauth2_cfg_ctx_t *oauth2_cfg_ctx_init(oauth2_log_t *log);
oauth2_cfg_ctx_t *oauth2_cfg_ctx_clone(oauth2_log_t *log,
				       oauth2_cfg_ctx_t *src);
void oauth2_cfg_ctx_free(oauth2_log_t *log, oauth2_cfg_ctx_t *ctx);

#define OAUTH2_TOKEN_VERIFY_BEARER_STR "bearer"
#define OAUTH2_TOKEN_VERIFY_DPOP_STR "dpop"
#define OAUTH2_TOKEN_VERIFY_MTLS_STR "mtls"

typedef struct oauth2_cfg_dpop_verify_t {
	oauth2_cache_t *cache;
	oauth2_time_t expiry_s;
	oauth2_jose_jwt_validate_claim_t iat_validate;
	oauth2_uint_t iat_slack_before;
	oauth2_uint_t iat_slack_after;
} oauth2_cfg_dpop_verify_t;

typedef enum oauth2_cfg_mtls_verify_policy_t {
	OAUTH2_MTLS_VERIFY_POLICY_OPTIONAL,
	OAUTH2_MTLS_VERIFY_POLICY_REQUIRED,
} oauth2_cfg_mtls_verify_policy_t;

typedef struct oauth2_cfg_mtls_verify_t {
	char *env_var_name;
	oauth2_cfg_mtls_verify_policy_t policy;
} oauth2_cfg_mtls_verify_t;

typedef struct oauth2_cfg_token_verify_t {
	oauth2_cfg_token_verify_cb_t *callback;
	oauth2_cfg_ctx_t *ctx;
	oauth2_cache_t *cache;
	oauth2_time_t expiry_s;
	oauth2_cfg_token_verify_type_t type;
	oauth2_cfg_dpop_verify_t dpop;
	oauth2_cfg_mtls_verify_t mtls;
	struct oauth2_cfg_token_verify_t *next;
} oauth2_cfg_token_verify_t;

typedef char *(oauth2_cfg_set_options_cb_t)(oauth2_log_t *log,
					    const char *value,
					    const oauth2_nv_list_t *params,
					    void *cfg);

#define _OAUTH_CFG_CTX_CALLBACK(name)                                          \
	char *name(oauth2_log_t *log, const char *value,                       \
		   const oauth2_nv_list_t *params, void *ctx)

typedef struct oauth2_cfg_set_options_ctx_t {
	const char *type;
	oauth2_cfg_set_options_cb_t *set_options_callback;
} oauth2_cfg_set_options_ctx_t;

char *oauth2_cfg_set_options(oauth2_log_t *log, void *cfg, const char *type,
			     const char *value, const char *options,
			     const oauth2_cfg_set_options_ctx_t *set);

/*
 * session
 */

bool oauth2_session_load_cookie(oauth2_log_t *log,
				const oauth2_cfg_session_t *cfg,
				oauth2_http_request_t *request, json_t **json);
bool oauth2_session_save_cookie(oauth2_log_t *log,
				const oauth2_cfg_session_t *cfg,
				const oauth2_http_request_t *request,
				oauth2_http_response_t *response, json_t *json);
bool oauth2_session_load_cache(oauth2_log_t *log,
			       const oauth2_cfg_session_t *cfg,
			       oauth2_http_request_t *request, json_t **json);
bool oauth2_session_save_cache(oauth2_log_t *log,
			       const oauth2_cfg_session_t *cfg,
			       const oauth2_http_request_t *request,
			       oauth2_http_response_t *response, json_t *json);

typedef enum oauth2_cfg_session_type_t {
	OAUTH2_SESSION_TYPE_COOKIE,
	OAUTH2_SESSION_TYPE_CACHE
} oauth2_cfg_session_type_t;

typedef struct oauth2_cfg_session_t {
	oauth2_cfg_session_type_t type;
	char *cookie_name;
	char *cookie_path;
	oauth2_time_t inactivity_timeout_s;
	oauth2_time_t max_duration_s;

	oauth2_cache_t *cache;

	oauth2_session_load_callback_t *load_callback;
	oauth2_session_save_callback_t *save_callback;
} oauth2_cfg_session_t;

void _oauth2_session_global_cleanup(oauth2_log_t *log);

/*
 * openidc
 */

typedef bool(oauth2_openidc_provider_resolver_func_t)(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *, char **);

typedef struct oauth2_cfg_openidc_provider_resolver_t {
	oauth2_openidc_provider_resolver_func_t *callback;
	oauth2_cfg_ctx_t *ctx;
	oauth2_cache_t *cache;
} oauth2_cfg_openidc_provider_resolver_t;

// TODO: set add log
typedef struct oauth2_cfg_openidc_t {

	char *handler_path;
	char *redirect_uri;

	oauth2_cfg_openidc_provider_resolver_t *provider_resolver;
	oauth2_openidc_client_t *client;

	oauth2_unauth_action_t unauth_action;

	oauth2_cfg_session_t *session;

	char *state_cookie_name_prefix;
	oauth2_time_t state_cookie_timeout;
	oauth2_uint_t state_cookie_max;
	oauth2_flag_t state_cookie_delete_oldest;
} oauth2_cfg_openidc_t;

/*
 * generic
 */

#define _OAUTH2_CFG_CTX_TYPE_START(type) typedef struct type##_t {

#define _OAUTH2_CFG_CTX_TYPE_END(type)                                         \
	}                                                                      \
	type##_t;

#define _OAUTH2_CFG_CTX_INIT_START(type)                                       \
	void *type##_init(oauth2_log_t *log)                                   \
	{                                                                      \
		type##_t *ctx = (type##_t *)oauth2_mem_alloc(sizeof(type##_t));

#define _OAUTH2_CFG_CTX_INIT_END                                               \
	return ctx;                                                            \
	}

#define _OAUTH2_CFG_CTX_CLONE_START(type)                                      \
	void *type##_clone(oauth2_log_t *log, void *s)                         \
	{                                                                      \
		type##_t *src = s;                                             \
		type##_t *dst = NULL;                                          \
		if (src == NULL)                                               \
			goto end;                                              \
		dst = type##_init(log);

#define _OAUTH2_CFG_CTX_CLONE_END                                              \
	end:                                                                   \
	return dst;                                                            \
	}

#define _OAUTH2_CFG_CTX_FREE_START(type)                                       \
	void type##_free(oauth2_log_t *log, void *c)                           \
	{                                                                      \
		type##_t *ctx = (type##_t *)c;

#define _OAUTH2_CFG_CTX_FREE_END                                               \
	if (ctx)                                                               \
		oauth2_mem_free(ctx);                                          \
	}

#define _OAUTH2_CFG_CTX_FUNCS(type)                                            \
	static oauth2_cfg_ctx_funcs_t type##_funcs = {                         \
	    type##_init, type##_clone, type##_free};

#define _OAUTH2_CFG_CTX_TYPE_SINGLE_STRING(type, member)                       \
	_OAUTH2_CFG_CTX_TYPE_START(type)                                       \
	char *member;                                                          \
	_OAUTH2_CFG_CTX_TYPE_END(type)                                         \
                                                                               \
	_OAUTH2_CFG_CTX_INIT_START(type)                                       \
	ctx->member = NULL;                                                    \
	_OAUTH2_CFG_CTX_INIT_END                                               \
                                                                               \
	_OAUTH2_CFG_CTX_CLONE_START(type)                                      \
	dst->member = oauth2_strdup(src->member);                              \
	_OAUTH2_CFG_CTX_CLONE_END                                              \
                                                                               \
	_OAUTH2_CFG_CTX_FREE_START(type)                                       \
	if (ctx->member)                                                       \
		oauth2_mem_free(ctx->member);                                  \
	_OAUTH2_CFG_CTX_FREE_END                                               \
                                                                               \
	_OAUTH2_CFG_CTX_FUNCS(type)

oauth2_cfg_session_t *_oauth2_cfg_session_obtain(oauth2_log_t *log,
						 const char *name);

#define _OAUTH2_CFG_GLOBAL_LIST(name, type)                                    \
	typedef void (*_oauth2_##name##_free_fn)(oauth2_log_t * log,           \
						 type * mtype);                \
                                                                               \
	typedef struct oauth2_##name##_list_t {                                \
		char *mname;                                                   \
		type *mtype;                                                   \
		_oauth2_##name##_free_fn free_fn;                              \
		struct oauth2_##name##_list_t *next;                           \
	} oauth2_##name##_list_t;                                              \
                                                                               \
	static oauth2_##name##_list_t *_oauth2_##name##_list = NULL;           \
	static oauth2_ipc_mutex_t *_oauth2_##name##_list_mutex = NULL;         \
                                                                               \
	static bool _M_##name##_list_lock(oauth2_log_t *log)                   \
	{                                                                      \
		bool rc = false;                                               \
		if (_oauth2_##name##_list_mutex == NULL) {                     \
			_oauth2_##name##_list_mutex =                          \
			    oauth2_ipc_mutex_init(log);                        \
			oauth2_ipc_mutex_post_config(                          \
			    log, _oauth2_##name##_list_mutex);                 \
		}                                                              \
		rc = oauth2_ipc_mutex_lock(log, _oauth2_##name##_list_mutex);  \
		return rc;                                                     \
	}                                                                      \
                                                                               \
	static bool _M_##name##_list_unlock(oauth2_log_t *log)                 \
	{                                                                      \
		bool rc = false;                                               \
		rc =                                                           \
		    oauth2_ipc_mutex_unlock(log, _oauth2_##name##_list_mutex); \
		return rc;                                                     \
	}                                                                      \
                                                                               \
	static void _M_##name##_list_register(                                 \
	    oauth2_log_t *log, const char *name, type *mtype,                  \
	    _oauth2_##name##_free_fn mfree_fn)                                 \
	{                                                                      \
		oauth2_##name##_list_t *ptr = NULL, *prev = NULL;              \
                                                                               \
		/*		oauth2_debug(log, "registering: %s", name); */             \
                                                                               \
		ptr = oauth2_mem_alloc(sizeof(oauth2_##name##_list_t));        \
		ptr->mname = oauth2_strdup(name);                              \
		ptr->mtype = mtype;                                            \
		ptr->next = NULL;                                              \
		ptr->free_fn = mfree_fn;                                       \
                                                                               \
		_M_##name##_list_lock(log);                                    \
                                                                               \
		if (_oauth2_##name##_list) {                                   \
			prev = _oauth2_##name##_list;                          \
			while (prev->next)                                     \
				prev = prev->next;                             \
			prev->next = ptr;                                      \
		} else {                                                       \
			_oauth2_##name##_list = ptr;                           \
		}                                                              \
                                                                               \
		_M_##name##_list_unlock(log);                                  \
	}                                                                      \
                                                                               \
	bool _M_##name##_list_empty(oauth2_log_t *log)                         \
	{                                                                      \
		return (_oauth2_##name##_list == NULL);                        \
	}                                                                      \
                                                                               \
	static type *_M_##name##_list_get(oauth2_log_t *log,                   \
					  const char *mname)                   \
	{                                                                      \
		oauth2_##name##_list_t *ptr = NULL, *match = NULL;             \
                                                                               \
		_M_##name##_list_lock(log);                                    \
                                                                               \
		ptr = _oauth2_##name##_list;                                   \
		while (ptr) {                                                  \
                                                                               \
			/*			oauth2_debug(log, "comparing:                     \
			 * \"%s\" with \%s\"", ptr->mname, mname); */          \
                                                                               \
			if ((mname) && (ptr->mname)) {                         \
				if (strcmp(ptr->mname, mname) == 0) {          \
					match = ptr;                           \
					break;                                 \
				}                                              \
			} else if ((mname == NULL) ||                          \
				   (strcmp("default", mname) == 0)) {          \
				match = ptr;                                   \
			}                                                      \
			ptr = ptr->next;                                       \
		}                                                              \
                                                                               \
		_M_##name##_list_unlock(log);                                  \
                                                                               \
		oauth2_debug(log, "returning: %p, %p, %s", match,              \
			     match ? match->mtype : NULL,                      \
			     match ? match->mname : NULL);                     \
                                                                               \
		return match ? match->mtype : NULL;                            \
	}                                                                      \
                                                                               \
	static void _M_##name##_list_release(oauth2_log_t *log)                \
	{                                                                      \
		oauth2_##name##_list_t *ptr = NULL;                            \
                                                                               \
		_M_##name##_list_lock(log);                                    \
                                                                               \
		while ((ptr = _oauth2_##name##_list)) {                        \
			_oauth2_##name##_list = _oauth2_##name##_list->next;   \
			if (ptr->free_fn)                                      \
				ptr->free_fn(log, ptr->mtype);                 \
			oauth2_mem_free(ptr->mname);                           \
			oauth2_mem_free(ptr);                                  \
		}                                                              \
                                                                               \
		_M_##name##_list_unlock(log);                                  \
                                                                               \
		if (_oauth2_##name##_list_mutex != NULL) {                     \
			oauth2_ipc_mutex_free(log,                             \
					      _oauth2_##name##_list_mutex);    \
			_oauth2_##name##_list_mutex = NULL;                    \
		}                                                              \
	}

#endif /* _OAUTH2_CFG_INT_H_ */
