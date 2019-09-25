#ifndef _OAUTH2_NGINX_H_
#define _OAUTH2_NGINX_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
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

#define OAUTH2_NGINX_CFG_FUNC_START(type, member, module, primitive)           \
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

#define OAUTH2_NGINX_CFG_FUNC_ARGS1(type, member, module, primitive)           \
	OAUTH2_NGINX_CFG_FUNC_START(type, member, module, primitive)           \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	rv = module##_set_##primitive(cfg->cfg, v1);                           \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

#define OAUTH2_NGINX_CFG_FUNC_ARGS2(type, member, module, primitive)           \
	OAUTH2_NGINX_CFG_FUNC_START(type, member, module, primitive)           \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	char *v2 = cf->args->nelts > 2                                         \
		       ? oauth2_strndup((const char *)value[2].data,           \
					(size_t)value[2].len)                  \
		       : NULL;                                                 \
	rv = module##_set_##primitive(cfg->cfg, v1, v2);                       \
	oauth2_mem_free(v2);                                                   \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

// commands

#define OAUTH2_NGINX_CMD(module, directive, primitive, take)                   \
	{                                                                      \
		ngx_string(directive), NGX_HTTP_LOC_CONF | take,               \
		    ngx_##module##_set_##primitive, NGX_HTTP_LOC_CONF_OFFSET,  \
		    0, NULL                                                    \
	}

#define OAUTH2_NGINX_CMD_TAKE1(module, directive, primitive)                   \
	OAUTH2_NGINX_CMD(module, directive, primitive, NGX_CONF_TAKE1)

#define OAUTH2_NGINX_CMD_TAKE12(module, directive, primitive)                  \
	OAUTH2_NGINX_CMD(module, directive, primitive, NGX_CONF_TAKE12)

#define OAUTH2_NGINX_CMD_TAKE23(module, directive, primitive)                  \
	OAUTH2_NGINX_CMD(module, directive, primitive, NGX_CONF_TAKE23)

#define OAUTH2_NGINX_CMD_TAKE123(module, directive, primitive)                 \
	OAUTH2_NGINX_CMD(module, directive, primitive, NGX_CONF_TAKE123)

#define OAUTH2_NGINX_CMD_TAKE34(module, directive, primitive)                  \
	OAUTH2_NGINX_CMD(module, directive, primitive,                         \
			 NGX_CONF_TAKE3 | NGX_CONF_TAKE4)

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

// clang-format off

#define _OAUTH2_NGINX_STRING_COPY(ctx, r_member, set_func)                      \
	char *v = (ctx->r->r_member.len > 0)                                   \
		      ? oauth2_strndup((const char *)ctx->r->r_member.data,    \
				       ctx->r->r_member.len)                   \
		      : NULL;                                                  \
	oauth2_http_request_##set_func##_set(ctx->log, ctx->request, v);       \
	oauth2_mem_free(v);

#define _OAUTH2_NGINX_START_END_COPY(ctx, r_member_start, r_member_end,         \
				    set_func)                                  \
	int len = ctx->r->r_member_end - ctx->r->r_member_start;               \
	char *v =                                                              \
	    (len > 0)                                                          \
		? oauth2_strndup((const char *)ctx->r->r_member_start, len)    \
		: NULL;                                                        \
	oauth2_http_request_##set_func##_set(ctx->log, ctx->request, v);       \
	oauth2_mem_free(v);

#define OAUTH2_NGINX_REQUEST_COPY_HACK \
		static void _oauth2_nginx_schema_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			_OAUTH2_NGINX_START_END_COPY(ctx, schema_start, schema_end, scheme); \
		} \
\
		static void _oauth2_nginx_host_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			_OAUTH2_NGINX_START_END_COPY(ctx, host_start, host_end, hostname); \
		} \
\
		static void _oauth2_nginx_port_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			char *v = NULL; \
			int len = ctx->r->port_end - ctx->r->port_start; \
			if (len > 0) { \
				v = oauth2_strndup((const char *)ctx->r->port_start, len); \
				oauth2_http_request_port_set(ctx->log, ctx->request, \
							     oauth2_parse_uint(NULL, v, 0)); \
				oauth2_mem_free(v); \
			} \
		} \
\
		static void _oauth2_nginx_path_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			_OAUTH2_NGINX_STRING_COPY(ctx, uri, path); \
		} \
\
		static void _oauth2_nginx_method_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			oauth2_http_method_t m = OAUTH2_HTTP_METHOD_UNKNOWN; \
			char *v = (ctx->r->method_name.len > 0) \
				      ? oauth2_strndup((const char *)ctx->r->method_name.data, \
						       ctx->r->method_name.len) \
				      : NULL; \
\
			if (v == NULL) \
				goto end; \
\
			if (strcmp(v, "GET") == 0) \
				m = OAUTH2_HTTP_METHOD_GET; \
			else if (strcmp(v, "POST") == 0) \
				m = OAUTH2_HTTP_METHOD_POST; \
			else if (strcmp(v, "PUT") == 0) \
				m = OAUTH2_HTTP_METHOD_PUT; \
			else if (strcmp(v, "DELETE") == 0) \
				m = OAUTH2_HTTP_METHOD_DELETE; \
			else if (strcmp(v, "CONNECT") == 0) \
				m = OAUTH2_HTTP_METHOD_CONNECT; \
			else if (strcmp(v, "OPTIONS") == 0) \
				m = OAUTH2_HTTP_METHOD_OPTIONS; \
\
			oauth2_http_request_method_set(ctx->log, ctx->request, m); \
\
		end: \
\
			if (v) \
				oauth2_mem_free(v); \
		} \
\
		static void _oauth2_nginx_query_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			_OAUTH2_NGINX_STRING_COPY(ctx, args, query); \
		} \
\
		static void _oauth2_nginx_headers_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			char *name = NULL, *value = NULL; \
			ngx_list_part_t *part; \
			ngx_table_elt_t *h; \
			ngx_uint_t i; \
			part = &ctx->r->headers_in.headers.part; \
			h = part->elts; \
			for (i = 0; /* void */; i++) { \
				if (i >= part->nelts) { \
					if (part->next == NULL) { \
						break; \
					} \
					part = part->next; \
					h = part->elts; \
					i = 0; \
				} \
				name = \
				    oauth2_strndup((const char *)h[i].key.data, h[i].key.len); \
				value = oauth2_strndup((const char *)h[i].value.data, \
						       h[i].value.len); \
				/* TODO: avoid duplicate copy */ \
				oauth2_http_request_header_add(ctx->log, ctx->request, name, \
							       value); \
				oauth2_mem_free(name); \
				oauth2_mem_free(value); \
			} \
		} \
\
		void _oauth2_nginx_request_copy(oauth2_nginx_request_context_t *ctx) \
		{ \
			_oauth2_nginx_schema_copy(ctx); \
			_oauth2_nginx_host_copy(ctx); \
			_oauth2_nginx_port_copy(ctx); \
			_oauth2_nginx_path_copy(ctx); \
			_oauth2_nginx_query_copy(ctx); \
			_oauth2_nginx_method_copy(ctx); \
			_oauth2_nginx_headers_copy(ctx); \
		} \

// clang-format off

#endif /* _OAUTH2_NGINX_H_ */
