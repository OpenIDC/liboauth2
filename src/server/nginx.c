/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV - www.zmartzone.eu
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "oauth2/nginx.h"

#include <oauth2/http.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>

#include <ngx_log.h>

// yep, this is tightly aligned with the (sequence of...) the log levels in
// lmo/log.h, but is faaast

// clang-format off
/*
static int log_level_nginx2oauth[] = {
    OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_WARN,
	OAUTH2_LOG_NOTICE,
	OAUTH2_LOG_INFO,
	OAUTH2_LOG_DEBUG
};
*/

// TODO: TRACE2 to STDERR??
static int log_level_log2nginx[] = {
    NGX_LOG_ERR,
	NGX_LOG_WARN,
	NGX_LOG_NOTICE,
	NGX_LOG_INFO,
    NGX_LOG_DEBUG,
	NGX_LOG_DEBUG,
	NGX_LOG_STDERR
};
// clang-format on

void oauth2_nginx_log(oauth2_log_sink_t *sink, const char *filename,
		      unsigned long line, const char *function,
		      oauth2_log_level_t level, const char *msg)
{
	// TODO: ngx_err_t?
	ngx_log_error_core(log_level_log2nginx[level],
			   (ngx_log_t *)oauth2_log_sink_ctx_get(sink), 0,
			   "# %s: %s", function, msg);
}

#define _OAUTH2_NGINX_STRING_COPY(ctx, r_member, set_func)                     \
	char *v = (ctx->r->r_member.len > 0)                                   \
		      ? oauth2_strndup((const char *)ctx->r->r_member.data,    \
				       ctx->r->r_member.len)                   \
		      : NULL;                                                  \
	oauth2_http_request_##set_func##_set(ctx->log, ctx->request, v);       \
	oauth2_mem_free(v);

#define _OAUTH2_NGINX_START_END_COPY(ctx, r_member_start, r_member_end,        \
				     set_func)                                 \
	int len = ctx->r->r_member_end - ctx->r->r_member_start;               \
	char *v =                                                              \
	    (len > 0)                                                          \
		? oauth2_strndup((const char *)ctx->r->r_member_start, len)    \
		: NULL;                                                        \
	oauth2_http_request_##set_func##_set(ctx->log, ctx->request, v);       \
	oauth2_mem_free(v);

static void _oauth2_nginx_schema_copy(oauth2_nginx_request_context_t *ctx)
{
	oauth2_http_request_scheme_set(
	    ctx->log, ctx->request,
	    ctx->r->http_connection->ssl == 1 ? "https" : "http");
}

static void _oauth2_nginx_host_copy(oauth2_nginx_request_context_t *ctx)
{
	_OAUTH2_NGINX_START_END_COPY(ctx, host_start, host_end, hostname);
}

static void _oauth2_nginx_port_copy(oauth2_nginx_request_context_t *ctx)
{
	char *v = NULL;
	int len = ctx->r->port_end - ctx->r->port_start;
	if (len > 0) {
		v = oauth2_strndup((const char *)ctx->r->port_start, len);
		oauth2_http_request_port_set(ctx->log, ctx->request,
					     oauth2_parse_uint(NULL, v, 0));
		oauth2_mem_free(v);
	}
}

static void _oauth2_nginx_path_copy(oauth2_nginx_request_context_t *ctx)
{
	_OAUTH2_NGINX_STRING_COPY(ctx, uri, path);
}

static void _oauth2_nginx_method_copy(oauth2_nginx_request_context_t *ctx)
{
	oauth2_http_method_t m = OAUTH2_HTTP_METHOD_UNKNOWN;
	char *v = (ctx->r->method_name.len > 0)
		      ? oauth2_strndup((const char *)ctx->r->method_name.data,
				       ctx->r->method_name.len)
		      : NULL;

	if (v == NULL)
		goto end;

	if (strcmp(v, "GET") == 0)
		m = OAUTH2_HTTP_METHOD_GET;
	else if (strcmp(v, "POST") == 0)
		m = OAUTH2_HTTP_METHOD_POST;
	else if (strcmp(v, "PUT") == 0)
		m = OAUTH2_HTTP_METHOD_PUT;
	else if (strcmp(v, "DELETE") == 0)
		m = OAUTH2_HTTP_METHOD_DELETE;
	else if (strcmp(v, "CONNECT") == 0)
		m = OAUTH2_HTTP_METHOD_CONNECT;
	else if (strcmp(v, "OPTIONS") == 0)
		m = OAUTH2_HTTP_METHOD_OPTIONS;

	oauth2_http_request_method_set(ctx->log, ctx->request, m);

end:

	if (v)
		oauth2_mem_free(v);
}

static void _oauth2_nginx_query_copy(oauth2_nginx_request_context_t *ctx)
{
	_OAUTH2_NGINX_STRING_COPY(ctx, args, query);
}

static void _oauth2_nginx_headers_copy(oauth2_nginx_request_context_t *ctx)
{
	char *name = NULL, *value = NULL;
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_uint_t i;
	part = &ctx->r->headers_in.headers.part;
	h = part->elts;
	for (i = 0; /* void */; i++) {
		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			h = part->elts;
			i = 0;
		}
		name =
		    oauth2_strndup((const char *)h[i].key.data, h[i].key.len);
		value = oauth2_strndup((const char *)h[i].value.data,
				       h[i].value.len);
		// TODO: avoid duplicate copy
		oauth2_http_request_header_add(ctx->log, ctx->request, name,
					       value);
		oauth2_mem_free(name);
		oauth2_mem_free(value);
	}
}

void _oauth2_nginx_request_copy(oauth2_nginx_request_context_t *ctx)
{
	if ((ctx == NULL) || (ctx->r == NULL))
		goto end;

	_oauth2_nginx_schema_copy(ctx);
	_oauth2_nginx_host_copy(ctx);
	_oauth2_nginx_port_copy(ctx);
	_oauth2_nginx_path_copy(ctx);
	_oauth2_nginx_query_copy(ctx);
	_oauth2_nginx_method_copy(ctx);
	_oauth2_nginx_headers_copy(ctx);

end:

	return;
}

static void _oauth2_nginx_ssl_cert_set(oauth2_nginx_request_context_t *ctx)
{
	ngx_str_t name;
	ngx_uint_t key;
	ngx_http_variable_value_t *vv = NULL;

	char *s_key = "ssl_client_cert";

	name.len = strlen(s_key);
	name.data = ngx_palloc(ctx->r->pool, name.len);
	memcpy(name.data, s_key, name.len);
	key = ngx_hash_strlow(name.data, name.data, name.len);
	vv = ngx_http_get_variable(ctx->r, &name, key);

	if ((vv == NULL) || (vv->not_found))
		return;

	char *s = oauth2_strndup((char *)vv->data, vv->len);
	oauth2_http_request_context_set(ctx->log, ctx->request,
					OAUTH2_TLS_CERT_VAR_NAME, s);

	ngx_pfree(ctx->r->pool, name.data);
	oauth2_mem_free(s);
}
oauth2_nginx_request_context_t *
oauth2_nginx_request_context_init(ngx_http_request_t *r)
{
	// ngx_http_core_srv_conf_t *cscf;
	oauth2_nginx_request_context_t *ctx = NULL;
	oauth2_log_sink_t *log_sink_nginx = NULL;

	//	if (r == NULL)
	//		goto end;

	// cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

	// TODO: memory allocation failure checks...?
	ctx = oauth2_mem_alloc(sizeof(oauth2_nginx_request_context_t));

	// TODO: get the log level from NGINX...
	oauth2_log_level_t level = OAUTH2_LOG_TRACE1;
	log_sink_nginx =
	    oauth2_log_sink_create(level, oauth2_nginx_log, r->connection->log);

	ctx->log = oauth2_log_init(level, log_sink_nginx);
	ctx->request = oauth2_http_request_init(ctx->log);
	ctx->r = r;

	_oauth2_nginx_request_copy(ctx);

	_oauth2_nginx_ssl_cert_set(ctx);

	oauth2_debug(ctx->log, "created NGINX request context: %p", ctx);

	// end:

	return ctx;
}

void oauth2_nginx_request_context_free(void *rec)
{
	oauth2_nginx_request_context_t *ctx =
	    (oauth2_nginx_request_context_t *)rec;
	if (ctx) {
		oauth2_debug(ctx->log, "dispose NGINX request context: %p",
			     ctx);
		if (ctx->request)
			oauth2_http_request_free(ctx->log, ctx->request);
		oauth2_log_free(ctx->log);
		oauth2_mem_free(ctx);
	}
}

static bool oauth2_nginx_response_header_set(oauth2_log_t *log, void *rec,
					     const char *name,
					     const char *value)
{
	bool rc = false;
	ngx_table_elt_t *h = NULL;
	ngx_http_request_t *r = (ngx_http_request_t *)rec;

	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL)
		goto end;

	h->hash = 1;
	h->key.len = strlen(name);
	h->key.data = ngx_palloc(r->pool, h->key.len);
	memcpy(h->key.data, name, h->key.len);
	h->value.len = strlen(value);
	h->value.data = ngx_palloc(r->pool, h->value.len);
	memcpy(h->value.data, value, h->value.len);

	rc = true;

end:

	return rc;
}

ngx_int_t oauth2_nginx_http_response_set(oauth2_log_t *log,
					 oauth2_http_response_t *response,
					 ngx_http_request_t *r)
{
	ngx_int_t nrc = NGX_ERROR;

	if ((response == NULL) || (r == NULL))
		goto end;

	oauth2_http_response_headers_loop(log, response,
					  oauth2_nginx_response_header_set, r);

	r->headers_out.status =
	    oauth2_http_response_status_code_get(log, response);

	if (r->headers_out.status == 200)
		nrc = NGX_OK;
	else if (r->headers_out.status == 302)
		nrc = NGX_HTTP_MOVED_TEMPORARILY;
	else if (r->headers_out.status == 401)
		nrc = NGX_HTTP_UNAUTHORIZED;
	else
		nrc = r->headers_out.status;

	// nrc = ngx_http_send_header(r);

end:

	return nrc;
}
