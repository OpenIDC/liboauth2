#ifndef _OAUTH2_NGINX_H_
#define _OAUTH2_NGINX_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
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

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_request.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oauth2/http.h>
#include <oauth2/log.h>
#include <oauth2/util.h>

// module

#define OAUTH2_NGINX_MODULE(module)                                            \
	extern ngx_module_t ngx_##module##_module;                             \
                                                                               \
	ngx_module_t *ngx_modules[] = {&ngx_##module##_module, NULL};          \
                                                                               \
	char *ngx_module_names[] = {OAUTH2_TOSTRING(ngx_##module##_module),    \
				    NULL};                                     \
                                                                               \
	char *ngx_module_order[] = {NULL};

// functions

#define OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	static char *ngx_##module##_set_##primitive(                           \
	    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)                    \
	{                                                                      \
		const char *rv = NULL;                                         \
		type *cfg = (type *)conf;                                      \
		ngx_str_t *value = cf->args->elts;
// fprintf(stderr, " ## %s: %p (log=%p)\n", __FUNCTION__, cfg, cf->log);

#define OAUTH2_NGINX_CFG_FUNC_END(cf, rv)                                      \
	if (rv)                                                                \
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, rv);                    \
	return rv ? NGX_CONF_ERROR : NGX_CONF_OK;                              \
	}

#define OAUTH2_NGINX_CFG_FUNC_RET1(module, type, primitive, func, member)      \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	(void)value;                                                           \
	rv = func(cf, &cfg->member);                                           \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

#define OAUTH2_NGINX_CFG_FUNC_ARGS1(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1);                                       \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

#define OAUTH2_NGINX_CFG_FUNC_ARGS2(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	char *v2 = cf->args->nelts > 2                                         \
		       ? oauth2_strndup((const char *)value[2].data,           \
					(size_t)value[2].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1, v2);                                   \
	oauth2_mem_free(v2);                                                   \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

#define OAUTH2_NGINX_CFG_FUNC_ARGS3(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	char *v2 = cf->args->nelts > 2                                         \
		       ? oauth2_strndup((const char *)value[2].data,           \
					(size_t)value[2].len)                  \
		       : NULL;                                                 \
	char *v3 = cf->args->nelts > 3                                         \
		       ? oauth2_strndup((const char *)value[3].data,           \
					(size_t)value[3].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1, v2, v3);                               \
	oauth2_mem_free(v3);                                                   \
	oauth2_mem_free(v2);                                                   \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

#define OAUTH2_NGINX_CFG_FUNC_ARGS4(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	char *v2 = cf->args->nelts > 2                                         \
		       ? oauth2_strndup((const char *)value[2].data,           \
					(size_t)value[2].len)                  \
		       : NULL;                                                 \
	char *v3 = cf->args->nelts > 3                                         \
		       ? oauth2_strndup((const char *)value[3].data,           \
					(size_t)value[3].len)                  \
		       : NULL;                                                 \
	char *v4 = cf->args->nelts > 4                                         \
		       ? oauth2_strndup((const char *)value[3].data,           \
					(size_t)value[4].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1, v2, v3, v4);                           \
	oauth2_mem_free(v4);                                                   \
	oauth2_mem_free(v3);                                                   \
	oauth2_mem_free(v2);                                                   \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

// commands

// clang-format off
#define OAUTH2_NGINX_CMD(take, module, directive, primitive)                   \
	{                                                                      \
		ngx_string(directive),                                         \
		    NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF |                    \
			NGX_CONF_TAKE##take,                                   \
		    ngx_##module##_set_##primitive, NGX_HTTP_LOC_CONF_OFFSET,  \
		    0, NULL                                                    \
	}
// clang-format on

// logging

void oauth2_nginx_log(oauth2_log_sink_t *sink, const char *filename,
		      unsigned long line, const char *function,
		      oauth2_log_level_t level, const char *msg);

// requests

typedef struct oauth2_nginx_request_context_t {
	oauth2_log_t *log;
	ngx_http_request_t *r;
	oauth2_http_request_t *request;
} oauth2_nginx_request_context_t;

oauth2_nginx_request_context_t *
oauth2_nginx_request_context_init(ngx_http_request_t *r);
void oauth2_nginx_request_context_free(void *rec);

ngx_int_t oauth2_nginx_http_response_set(oauth2_log_t *log,
					 oauth2_http_response_t *response,
					 ngx_http_request_t *r);

//

char *oauth2_nginx_str2chr(ngx_pool_t *p, const ngx_str_t *str);

#define OAUTH2_NGINX_CMD_SET_IMPL(module, primitive)                           \
	static ngx_int_t ngx_##module##_##primitive##_variable(                \
	    ngx_http_request_t *r, ngx_http_variable_value_t *v,               \
	    uintptr_t data)                                                    \
	{                                                                      \
		return oauth2_nginx_##primitive##_variable(                    \
		    ngx_##module##_module, r, v, data);                        \
	}                                                                      \
                                                                               \
	static char *ngx_##module##_set_##primitive(                           \
	    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)                    \
	{                                                                      \
		return oauth2_nginx_set_##primitive(                           \
		    ngx_##module##_module,                                     \
		    ngx_##module##_##primitive##_variable, cf, cmd, conf);     \
	}

ngx_int_t oauth2_nginx_claim_variable(ngx_module_t module,
				      ngx_http_request_t *r,
				      ngx_http_variable_value_t *v,
				      uintptr_t data);
char *oauth2_nginx_set_claim(ngx_module_t module,
			     ngx_http_get_variable_pt handler, ngx_conf_t *cf,
			     ngx_command_t *cmd, void *conf);
ngx_int_t oauth2_nginx_set_target_variables(ngx_module_t module,
					    oauth2_nginx_request_context_t *ctx,
					    json_t *json_token);
char *nginx_oauth2_set_require(ngx_conf_t *cf, ngx_array_t **requirements);
ngx_int_t nginx_oauth2_check_requirements(oauth2_nginx_request_context_t *ctx,
					  ngx_array_t *requirements);

#endif /* _OAUTH2_NGINX_H_ */
