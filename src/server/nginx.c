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
	in_port_t port = 0;
	struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6 *sin6;
#endif

	switch (ctx->r->connection->local_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
	case AF_INET6:
		sin6 =
		    (struct sockaddr_in6 *)ctx->r->connection->local_sockaddr;
		port = ntohs(sin6->sin6_port);
		break;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
	case AF_UNIX:
		port = 0;
		break;
#endif
	default: /* AF_INET */
		sin = (struct sockaddr_in *)ctx->r->connection->local_sockaddr;
		port = ntohs(sin->sin_port);
	}

	oauth2_http_request_port_set(ctx->log, ctx->request,
				     (unsigned long)port);
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

	if ((vv == NULL) || (vv->not_found)) {
		ngx_pfree(ctx->r->pool, name.data);
		return;
	}

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

typedef struct oauth2_nginx_claim_hash_t {
	ngx_hash_keys_arrays_t keys;
	ngx_hash_t h;
} oauth2_nginx_claim_hash_t;

static inline ngx_str_t oauth2_nginx_chr2str(ngx_pool_t *p, const char *k)
{
	ngx_str_t in = {strlen(k), (u_char *)k};
	ngx_str_t out = {in.len, ngx_pstrdup(p, &in)};
	return out;
}

char *oauth2_nginx_str2chr(ngx_pool_t *p, const ngx_str_t *str)
{
	char *s = ngx_pnalloc(p, str->len + 1);
	if (s != NULL) {
		memcpy(s, str->data, str->len);
		s[str->len] = '\0';
	}
	return s;
}

static inline char *oauth2_nginx_chr2chr(ngx_pool_t *p, const char *str)
{
	ngx_str_t s = {strlen(str), (u_char *)str};
	return oauth2_nginx_str2chr(p, &s);
}

ngx_int_t oauth2_nginx_claim_variable(ngx_module_t module,
				      ngx_http_request_t *r,
				      ngx_http_variable_value_t *v,
				      uintptr_t data)
{
	oauth2_nginx_claim_hash_t *claims = NULL;
	const char *value = NULL;
	ngx_str_t key = {strlen((const char *)data), (u_char *)data};

	claims =
	    (oauth2_nginx_claim_hash_t *)ngx_http_get_module_ctx(r, module);

	if (claims == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	value = (const char *)ngx_hash_find(
	    &claims->h, ngx_hash_key(key.data, key.len), key.data, key.len);

	if (value != NULL) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			       "oauth2_nginx_claim_variable: %V=%s", &key,
			       value);
		v->data = (u_char *)value;
		v->len = strlen(value);
		v->no_cacheable = 1;
		v->not_found = 0;
	} else {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			       "oauth2_nginx_claim_variable: %V=(null)", &key);
		v->not_found = 1;
	}

	return NGX_OK;
}

static const size_t OAUTH2_NGINX_MAX_BUF = 128;

char *oauth2_nginx_set_claim(ngx_module_t module,
			     ngx_http_get_variable_pt handler, ngx_conf_t *cf,
			     ngx_command_t *cmd, void *conf)
{
	ngx_http_variable_t *v;
	char buf[OAUTH2_NGINX_MAX_BUF];
	int n = 0;
	char *s = NULL;
	ngx_str_t *value = cf->args->elts;

	if (value[2].len <= 1 || value[2].data[0] != '$') {
		n = snprintf(buf, sizeof(buf), "Invalid variable name %.*s",
			     (int)value[2].len, value[2].data);
		ngx_str_t msg = {n, (u_char *)&buf[0]};
		s = oauth2_nginx_str2chr(cf->pool, &msg);
		return s ? s : NGX_CONF_ERROR;
	}

	value[2].len--;
	value[2].data++;

	v = ngx_http_add_variable(cf, &value[2], NGX_HTTP_VAR_CHANGEABLE);
	if (!v) {
		ngx_str_t msg = ngx_string("ngx_http_add_variable failed");
		s = oauth2_nginx_str2chr(cf->pool, &msg);
		return s ? s : NGX_CONF_ERROR;
	}

	v->get_handler = handler;
	char *claim = oauth2_nginx_str2chr(cf->pool, &value[1]);
	if (!claim) {
		ngx_str_t msg = ngx_string("Out of memory");
		s = oauth2_nginx_str2chr(cf->pool, &msg);
		return s ? s : NGX_CONF_ERROR;
	}
	v->data = (uintptr_t)claim;

	return NGX_CONF_OK;
}

static ngx_int_t ngx_set_target_variable(oauth2_nginx_claim_hash_t *claims,
					 oauth2_nginx_request_context_t *ctx,
					 const char *k, const char *v)
{
	ngx_str_t key = oauth2_nginx_chr2str(claims->keys.pool, k);
	if (key.data == NULL)
		return NGX_ERROR;
	const char *value = oauth2_nginx_chr2chr(claims->keys.pool, v);
	if (value == NULL)
		return NGX_ERROR;
	return ngx_hash_add_key(&claims->keys, &key, (char *)value,
				NGX_HASH_READONLY_KEY);
}

static ngx_int_t ngx_oauth2_init_keys(ngx_pool_t *pool,
				      oauth2_nginx_claim_hash_t *claims)
{
	claims->keys.pool = pool;
	claims->keys.temp_pool = pool;
	return ngx_hash_keys_array_init(&claims->keys, NGX_HASH_SMALL);
}

static ngx_int_t ngx_oauth2_init_hash(ngx_pool_t *pool,
				      oauth2_nginx_claim_hash_t *claims)
{
	ngx_hash_init_t init;
	init.hash = &claims->h;
	init.key = ngx_hash_key;
	init.max_size = 64;
	init.bucket_size = ngx_align(64, ngx_cacheline_size);
	init.name = "claims";
	init.pool = pool;
	init.temp_pool = pool;
	return ngx_hash_init(&init, claims->keys.keys.elts,
			     claims->keys.keys.nelts);
}

ngx_int_t oauth2_nginx_set_target_variables(ngx_module_t module,
					    oauth2_nginx_request_context_t *ctx,
					    json_t *json_token)
{
	void *iter = NULL;
	const char *key = NULL, *val = NULL;
	json_t *value = NULL;
	oauth2_nginx_claim_hash_t *claims = NULL;
	int rc = NGX_OK;

	claims = (oauth2_nginx_claim_hash_t *)ngx_http_get_module_ctx(ctx->r,
								      module);

	if (claims == NULL) {

		claims = ngx_palloc(ctx->r->pool, sizeof(*claims));

		if (claims == NULL) {
			oauth2_error(ctx->log, "error allocating claims hash");
			return NGX_ERROR;
		}

		rc = ngx_oauth2_init_keys(ctx->r->pool, claims);

		if (rc != NGX_OK) {
			oauth2_error(ctx->log,
				     "error %d initializing hash keys", rc);
			return rc;
		}

		ngx_http_set_ctx(ctx->r, claims, module);
	}

	iter = json_object_iter(json_token);
	while (iter) {

		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);

		if (json_is_string(value)) {
			rc = ngx_set_target_variable(claims, ctx, key,
						     json_string_value(value));
		} else {
			val = oauth2_json_encode(ctx->log, value,
						 JSON_ENCODE_ANY);
			rc = ngx_set_target_variable(claims, ctx, key, val);
			oauth2_mem_free((char *)val);
		}

		if (rc != NGX_OK) {
			oauth2_error(
			    ctx->log,
			    "error %d setting value of key %s in claims hash",
			    rc, key);
			return rc;
		}

		iter = json_object_iter_next(json_token, iter);
	}

	rc = ngx_oauth2_init_hash(ctx->r->pool, claims);

	if (rc != NGX_OK) {
		oauth2_error(ctx->log, "error %d initializing claims hash", rc);
		return rc;
	}

	return NGX_OK;
}

char *nginx_oauth2_set_require(ngx_conf_t *cf, ngx_array_t **requirements)
{
	ngx_http_complex_value_t *val = NULL;
	ngx_http_compile_complex_value_t ccv;
	ngx_str_t *var = NULL;
	int rc = NGX_OK;
	char *s = NULL;
	char buf[OAUTH2_NGINX_MAX_BUF];

	if (cf->args == NULL)
		return NGX_CONF_ERROR;

	if (*requirements == NULL) {
		*requirements =
		    ngx_array_create(cf->pool, cf->args->nelts,
				     sizeof(ngx_http_complex_value_t));
		if (*requirements == NULL) {
			ngx_str_t msg = ngx_string("Out of memory");
			s = oauth2_nginx_str2chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}

	for (unsigned int i = 1; i < cf->args->nelts; ++i) {

		var = (ngx_str_t *)cf->args->elts + i;
		/* no allocation here because we've already dimensioned the
		 * array upon its creation */
		val = (ngx_http_complex_value_t *)ngx_array_push(*requirements);

		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf = cf;
		ccv.value = var;
		ccv.complex_value = val;

		rc = ngx_http_compile_complex_value(&ccv);
		if (rc != NGX_OK) {
			int n = snprintf(buf, sizeof(buf),
					 "Error %d compiling "
					 "expression %.*s",
					 rc, (int)var->len, var->data);
			ngx_str_t msg = {n, (u_char *)&buf[0]};
			s = oauth2_nginx_str2chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t
nginx_oauth2_check_requirement(oauth2_nginx_request_context_t *ctx,
			       ngx_http_complex_value_t *cv)
{
	ngx_str_t v;
	ngx_int_t rc = ngx_http_complex_value(ctx->r, cv, &v);
	if (rc != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
			      "error %d evaluating expression %*.s", rc,
			      (int)cv->value.len, cv->value.data);
		return NGX_ERROR;
	}

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
		       "nginx_oauth2_check_requirement: expression \"%*.s\" "
		       "evaluated to: %s",
		       (int)cv->value.len, cv->value.data,
		       (1 == v.len && '1' == *v.data)
			   ? "NGX_OK"
			   : "NGX_HTTP_UNAUTHORIZED");

	return 1 == v.len && '1' == *v.data ? NGX_OK : NGX_HTTP_UNAUTHORIZED;
}
ngx_int_t nginx_oauth2_check_requirements(oauth2_nginx_request_context_t *ctx,
					  ngx_array_t *requirements)
{
	int rc = NGX_OK;
	ngx_uint_t i = 0;

	if (requirements == NULL)
		return NGX_OK;

	for (i = 0; i < requirements->nelts; ++i) {
		ngx_http_complex_value_t *cv =
		    (ngx_http_complex_value_t *)requirements->elts + i;
		rc = nginx_oauth2_check_requirement(ctx, cv);
		if (rc != NGX_OK)
			break;
	}

	return rc;
}
