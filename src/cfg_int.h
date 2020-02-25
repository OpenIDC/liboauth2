#ifndef _OAUTH2_CFG_INT_H_
#define _OAUTH2_CFG_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2020 - ZmartZone Holding BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include "oauth2/cache.h"
#include "oauth2/cfg.h"
#include "oauth2/oauth2.h"
#include "oauth2/openidc.h"
#include "oauth2/session.h"

#include <cjose/cjose.h>

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

typedef struct oauth2_cfg_token_verify_t {
	oauth2_cfg_token_verify_cb_t *callback;
	oauth2_cfg_ctx_t *ctx;
	oauth2_cache_t *cache;
	oauth2_time_t expiry_s;
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

typedef struct oauth2_cfg_session_t {
	oauth2_cfg_session_type_t type;
	char *cookie_name;
	oauth2_time_t inactivity_timeout_s;
	oauth2_time_t max_duration_s;

	char *passphrase;

	oauth2_cache_t *cache;

	oauth2_session_load_callback_t *load_callback;
	oauth2_session_save_callback_t *save_callback;
	// TODO: free callback (init is done through set options)
} oauth2_cfg_session_t;

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
	oauth2_unauth_action_t unauth_action;
	char *state_cookie_name_prefix;
	char *passphrase;
	oauth2_cfg_session_t *session;
} oauth2_cfg_openidc_t;

#define OAUTH2_OPENIDC_STATE_COOKIE_NAME_PREFIX_DEFAULT "openidc_state_"

char *oauth2_openidc_cfg_state_cookie_name_prefix_get(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg);

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

#endif /* _OAUTH2_CFG_INT_H_ */
