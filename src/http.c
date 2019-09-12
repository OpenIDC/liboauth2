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

#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

#include "oauth2/http.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"
#include "oauth2/version.h"
#include "util_int.h"

/*
 * request
 */

typedef struct oauth2_http_request_t {
	//	oauth2_http_server_t *server;
	oauth2_nv_list_t *header;
	char *scheme;
	unsigned long port;
	char *hostname;
	oauth2_uint_t method;
	char *path;
	char *query;
	oauth2_nv_list_t *_parsed_query;
	oauth2_nv_list_t *_parsed_cookies;
} oauth2_http_request_t;

// TODO: provide scheme as part of init?
oauth2_http_request_t *oauth2_http_request_init(oauth2_log_t *log)
{
	oauth2_http_request_t *request = NULL;

	request = oauth2_mem_alloc(sizeof(oauth2_http_request_t));
	if (request == NULL)
		goto end;

	request->header = oauth2_nv_list_init(log);
	oauth2_nv_list_case_sensitive_set(log, request->header, false);

	request->scheme = NULL;
	request->hostname = NULL;
	request->port = 0;
	request->method = 0;
	request->path = NULL;
	request->query = NULL;

	request->_parsed_query = NULL;
	request->_parsed_cookies = NULL;

end:

	return request;
}

void oauth2_http_request_free(oauth2_log_t *log, oauth2_http_request_t *request)
{
	if (request == NULL)
		goto end;

	oauth2_nv_list_free(log, request->_parsed_query);
	oauth2_nv_list_free(log, request->_parsed_cookies);

	oauth2_nv_list_free(log, request->header);

	if (request->scheme)
		oauth2_mem_free(request->scheme);
	if (request->hostname)
		oauth2_mem_free(request->hostname);
	if (request->path)
		oauth2_mem_free(request->path);
	if (request->query)
		oauth2_mem_free(request->query);

	oauth2_mem_free(request);

end:

	return;
}

_OAUTH2_MEMBER_LIST_IMPLEMENT_UNSET_GET(http, request, header)

void oauth2_http_request_headers_loop(oauth2_log_t *log,
				      oauth2_http_request_t *request,
				      oauth2_nv_list_loop_cb_t *callback,
				      void *rec)
{
	oauth2_nv_list_loop(log, request->header, callback, rec);
}

/*
 * headers
 */

typedef bool(_oauth2_nv_list_set_add_sanitize_cb_t)(oauth2_log_t *,
						    oauth2_nv_list_t *,
						    const char *, const char *);

static bool _oauth2_http_request_header_set_add_sanitized(
    oauth2_log_t *log, oauth2_http_request_t *request, const char *name,
    const char *value, _oauth2_nv_list_set_add_sanitize_cb_t add_set_cb)
{
	bool rc = false;
	char *s_value = NULL, *p = NULL;

	if ((request == NULL) && (name == NULL))
		goto end;

	if (value) {

		s_value = oauth2_strdup(value);

		if (s_value == NULL)
			goto end;

		/*
		 * sanitize the header value by replacing line feeds with spaces
		 * just like the Apache header input algorithms do for incoming
		 * headers
		 *
		 * this makes it impossible to have line feeds in values but
		 * that is
		 * compliant with RFC 7230 (and impossible for regular headers
		 * due to Apache's
		 * parsing of headers anyway) and fixes a security vulnerability
		 * on
		 * overwriting/setting outgoing headers when used in proxy mode
		 */
		while ((p = strchr(s_value, '\n')))
			*p = ' ';
	}

	oauth2_debug(log, "%s: %s", name, s_value ? s_value : "(null)");

	rc = add_set_cb(log, request->header, name, s_value);

end:

	if (s_value)
		oauth2_mem_free(s_value);

	return rc;
}

bool oauth2_http_request_header_set(oauth2_log_t *log,
				    oauth2_http_request_t *request,
				    const char *name, const char *value)
{
	return _oauth2_http_request_header_set_add_sanitized(
	    log, request, name, value, oauth2_nv_list_set);
}

bool oauth2_http_request_header_add(oauth2_log_t *log,
				    oauth2_http_request_t *request,
				    const char *name, const char *value)
{
	return _oauth2_http_request_header_set_add_sanitized(
	    log, request, name, value, oauth2_nv_list_add);
}

static char *oauth2_http_request_header_get_left_most_only(
    oauth2_log_t *log, const oauth2_http_request_t *request, const char *name)
{
	char *rv = NULL, *v = NULL;
	const char *value = NULL;
	const char *separators = ", \t";
	value = oauth2_http_request_header_get(log, request, name);
	if (value == NULL)
		goto end;

	v = oauth2_strdup(value);
	if (v)
		rv = strtok(v, separators);

end:
	return rv;
}

static char *
oauth2_http_request_header_x_forwarded_proto_get(oauth2_log_t *log,
						 const oauth2_http_request_t *r)
{
	return oauth2_http_request_header_get_left_most_only(
	    log, r, OAUTH2_HTTP_HDR_X_FORWARDED_PROTO);
}

static char *oauth2_http_request_header_x_forwarded_port_get(
    oauth2_log_t *log, const oauth2_http_request_t *request)
{
	return oauth2_http_request_header_get_left_most_only(
	    log, request, OAUTH2_HTTP_HDR_X_FORWARDED_PORT);
}

static char *oauth2_http_request_header_x_forwarded_host_get(
    oauth2_log_t *log, const oauth2_http_request_t *request)
{
	return oauth2_http_request_header_get_left_most_only(
	    log, request, OAUTH2_HTTP_HDR_X_FORWARDED_HOST);
}

static char *
oauth2_http_request_header_host_get(oauth2_log_t *log,
				    const oauth2_http_request_t *request)
{
	return oauth2_strdup(
	    oauth2_http_request_header_get(log, request, OAUTH2_HTTP_HDR_HOST));
}

const char *oauth2_http_request_header_content_type_get(
    oauth2_log_t *log, const oauth2_http_request_t *request)
{
	return oauth2_http_request_header_get(log, request,
					      OAUTH2_HTTP_HDR_CONTENT_TYPE);
}

const char *oauth2_http_request_header_content_length_get(
    oauth2_log_t *log, const oauth2_http_request_t *request)
{
	return oauth2_http_request_header_get(log, request,
					      OAUTH2_HTTP_HDR_CONTENT_LENGTH);
}

const char *oauth2_http_request_header_x_requested_with_get(
    oauth2_log_t *log, const oauth2_http_request_t *request)
{
	return oauth2_http_request_header_get(log, request,
					      OAUTH2_HTTP_HDR_X_REQUESTED_WITH);
}

const char *
oauth2_http_request_header_accept_get(oauth2_log_t *log,
				      const oauth2_http_request_t *request)
{
	return oauth2_http_request_header_get(log, request,
					      OAUTH2_HTTP_HDR_ACCEPT);
}

#define OAUTH2_HTTP_HDR_CONTENT_LENGTH_MAX 256

bool oauth2_http_request_header_content_length_set(
    oauth2_log_t *log, oauth2_http_request_t *request, size_t len)
{
	char str[OAUTH2_HTTP_HDR_CONTENT_LENGTH_MAX];
	oauth2_snprintf(str, OAUTH2_HTTP_HDR_CONTENT_LENGTH_MAX, "%lu", len);
	return oauth2_http_request_header_set(
	    log, request, OAUTH2_HTTP_HDR_CONTENT_LENGTH, str);
}

const char *
oauth2_http_request_header_cookie_get(oauth2_log_t *log,
				      const oauth2_http_request_t *request)
{
	return oauth2_http_request_header_get(log, request,
					      OAUTH2_HTTP_HDR_COOKIE);
}

static bool _oauth2_http_request_header_cookie_set(
    oauth2_log_t *log, oauth2_http_request_t *request, const char *value)
{
	return oauth2_http_request_header_set(log, request,
					      OAUTH2_HTTP_HDR_COOKIE, value);
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, request, scheme, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, request, hostname, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(http, request, path, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(http, request, method,
				      oauth2_http_method_t, uint)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(http, request, query, char *, str)

/*
 * current request URI
 */

char *oauth2_http_request_scheme_get(oauth2_log_t *log,
				     const oauth2_http_request_t *request)
{
	char *scheme_str = NULL;

	if (request == NULL)
		goto end;

	scheme_str =
	    oauth2_http_request_header_x_forwarded_proto_get(log, request);

	if (scheme_str == NULL)
		scheme_str = oauth2_strdup(request->scheme);

	if ((scheme_str == NULL) ||
	    ((strcmp(scheme_str, OAUTH2_HTTP_SCHEME_HTTP) != 0) &&
	     (strcmp(scheme_str, OAUTH2_HTTP_SCHEME_HTTPS) != 0))) {
		oauth2_warn(log,
			    "detected HTTP scheme \"%s\" is not \"%s\" nor "
			    "\"%s\"; perhaps your reverse proxy passes a "
			    "wrongly configured \"%s\" header: falling back "
			    "to default \"%s\"",
			    scheme_str, OAUTH2_HTTP_SCHEME_HTTP,
			    OAUTH2_HTTP_SCHEME_HTTPS,
			    OAUTH2_HTTP_HDR_X_FORWARDED_PROTO,
			    OAUTH2_HTTP_SCHEME_HTTPS);
		scheme_str = oauth2_strdup(OAUTH2_HTTP_SCHEME_HTTPS);
	}

end:

	return scheme_str;
}

bool oauth2_http_request_port_set(oauth2_log_t *log,
				  oauth2_http_request_t *request,
				  unsigned long port)
{
	request->port = port;
	return (request->port > 0);
}

#define OAUTH2_PORT_STR_MAX 16

char *oauth2_http_request_port_get(oauth2_log_t *log,
				   const oauth2_http_request_t *request)
{

	char *proto_str = NULL, *port_str = NULL, *scheme_str = NULL;

	port_str =
	    oauth2_http_request_header_x_forwarded_port_get(log, request);
	if (port_str)
		goto end;

	char *host_hdr =
	    oauth2_http_request_header_x_forwarded_host_get(log, request);
	if (host_hdr) {
		port_str = strchr(host_hdr, _OAUTH2_CHAR_COLON);
		if (port_str) {
			port_str++;
			port_str = oauth2_strdup(port_str);
		}
		oauth2_mem_free(host_hdr);
		goto end;
	}

	host_hdr = oauth2_http_request_header_host_get(log, request);
	if (host_hdr) {
		port_str = strchr(host_hdr, _OAUTH2_CHAR_COLON);
		if (port_str) {
			port_str++;
			port_str = oauth2_strdup(port_str);
		}
		oauth2_mem_free(host_hdr);
		if (port_str)
			goto end;
	}

	proto_str =
	    oauth2_http_request_header_x_forwarded_proto_get(log, request);
	if (proto_str)
		goto end;

	unsigned long port = request->port;

	scheme_str = oauth2_http_request_scheme_get(log, request);
	if (scheme_str) {
		if ((strcasecmp(scheme_str, OAUTH2_HTTP_SCHEME_HTTPS) == 0) &&
		    port == 443)
			goto end;
		else if ((strcasecmp(scheme_str, OAUTH2_HTTP_SCHEME_HTTP) ==
			  0) &&
			 port == 80)
			goto end;
	}

	if (port > 0) {
		port_str = oauth2_mem_alloc(OAUTH2_PORT_STR_MAX);
		oauth2_snprintf(port_str, OAUTH2_PORT_STR_MAX, "%lu", port);
	}

end:
	if (proto_str)
		oauth2_mem_free(proto_str);
	if (scheme_str)
		oauth2_mem_free(scheme_str);

	return port_str;
}

char *oauth2_http_request_hostname_get(oauth2_log_t *log,
				       const oauth2_http_request_t *request)
{
	char *host_str = NULL;

	if (request == NULL)
		goto end;

	host_str =
	    oauth2_http_request_header_x_forwarded_host_get(log, request);

	if (host_str == NULL)
		host_str = oauth2_http_request_header_host_get(log, request);

	if (host_str) {
		char *p = strchr(host_str, _OAUTH2_CHAR_COLON);
		if (p != NULL)
			*p = '\0';
		goto end;
	}

	if (request->hostname)
		host_str = oauth2_strdup(request->hostname);

end:

	return host_str;
}

char *oauth2_http_request_url_base_get(oauth2_log_t *log,
				       const oauth2_http_request_t *request)
{

	// TODO: store static in request so this is evaluated only once for each
	// request
	//       or do we want to allow dynamically inserted header evaluation?

	char *url = NULL, *host_str = NULL, *port_str = NULL;

	if (request == NULL)
		goto end;

	url = oauth2_http_request_scheme_get(log, request);
	if (url == NULL)
		goto end;

	host_str = oauth2_http_request_hostname_get(log, request);
	if (host_str == NULL) {
		oauth2_mem_free(url);
		url = NULL;
		goto end;
	}

	port_str = oauth2_http_request_port_get(log, request);

	url = _oauth2_stradd4(url, "://", host_str, port_str ? ":" : NULL,
			      port_str);

end:

	if (host_str)
		oauth2_mem_free(host_str);
	if (port_str)
		oauth2_mem_free(port_str);

	return url;
}

char *oauth2_http_request_url_get(oauth2_log_t *log,
				  const oauth2_http_request_t *request)
{

	char *url = NULL, *base_str = NULL, *path_str = NULL, *query_str = NULL,
	     *sep = NULL;

	base_str = oauth2_http_request_url_base_get(log, request);
	if (base_str == NULL)
		goto end;

	// TODO: in Apache r->path (or r->uri) can be absolute
	//       for forwarding proxy setups; are we dealing with that?
	path_str = request->path ? request->path : "";

	// TODO: query_args_add http until function
	sep = (request->query && *request->query != '\0') ? _OAUTH2_STR_QMARK
							  : "";
	query_str = request->query ? request->query : "";

	url = _oauth2_stradd4(url, base_str, path_str, sep, query_str);

end:

	oauth2_debug(log, "%s", url);

	if (base_str)
		oauth2_mem_free(base_str);

	return url;
}

/*
 * oauth2_http_call_ctx_t
 */

typedef struct oauth2_http_call_ctx_t {
	char *basic_auth_username;
	char *basic_auth_password;
	char *bearer_token;
	int timeout;
	bool ssl_verify;
	char *outgoing_proxy;
	oauth2_nv_list_t *cookie;
	oauth2_nv_list_t *hdr;
	char *ca_info;
	char *ssl_cert;
	char *ssl_key;
	char *to_str;
} oauth2_http_call_ctx_t;

#define OAUTH2_HTTP_CALL_TIMEOUT_DEFAULT 15
#define OAUTH2_HTTP_CALL_SSL_VERIFY_DEFAULT true

oauth2_http_call_ctx_t *oauth2_http_call_ctx_init(oauth2_log_t *log)
{

	oauth2_http_call_ctx_t *ctx = NULL;

	ctx = oauth2_mem_alloc(sizeof(oauth2_http_call_ctx_t));
	if (ctx == NULL)
		goto end;

	oauth2_http_call_ctx_timeout_set(log, ctx,
					 OAUTH2_HTTP_CALL_TIMEOUT_DEFAULT);
	oauth2_http_call_ctx_ssl_verify_set(
	    log, ctx, OAUTH2_HTTP_CALL_SSL_VERIFY_DEFAULT);
	oauth2_http_call_ctx_outgoing_proxy_set(log, ctx, NULL);
	oauth2_http_call_ctx_ca_info_set(log, ctx, NULL);
	oauth2_http_call_ctx_ssl_cert_set(log, ctx, NULL);
	oauth2_http_call_ctx_ssl_key_set(log, ctx, NULL);

	ctx->cookie = oauth2_nv_list_init(log);
	ctx->hdr = oauth2_nv_list_init(log);
	oauth2_nv_list_case_sensitive_set(log, ctx->hdr, false);

	ctx->to_str = NULL;

end:

	return ctx;
}

void oauth2_http_call_ctx_free(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx)
{
	if (ctx == NULL)
		goto end;

	if (ctx->basic_auth_username)
		oauth2_mem_free(ctx->basic_auth_username);
	if (ctx->basic_auth_password)
		oauth2_mem_free(ctx->basic_auth_password);
	if (ctx->bearer_token)
		oauth2_mem_free(ctx->bearer_token);
	if (ctx->outgoing_proxy)
		oauth2_mem_free(ctx->outgoing_proxy);
	if (ctx->ca_info)
		oauth2_mem_free(ctx->ca_info);
	if (ctx->ssl_cert)
		oauth2_mem_free(ctx->ssl_cert);
	if (ctx->ssl_key)
		oauth2_mem_free(ctx->ssl_key);
	if (ctx->cookie)
		oauth2_nv_list_free(log, ctx->cookie);
	if (ctx->hdr)
		oauth2_nv_list_free(log, ctx->hdr);
	if (ctx->to_str)
		oauth2_mem_free(ctx->to_str);

	oauth2_mem_free(ctx);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, call_ctx, timeout, int, integer)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, call_ctx, ssl_verify, bool, bln)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, call_ctx, outgoing_proxy, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, call_ctx, ca_info, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, call_ctx, ssl_cert, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(http, call_ctx, ssl_key, char *, str)
_OAUTH2_MEMBER_LIST_IMPLEMENT_SET_ADD_UNSET_GET(http, call_ctx, cookie);
_OAUTH2_MEMBER_LIST_IMPLEMENT_SET_ADD_UNSET_GET(http, call_ctx, hdr);

bool oauth2_http_call_ctx_content_type_set(oauth2_log_t *log,
					   oauth2_http_call_ctx_t *ctx,
					   const char *content_type)
{
	return oauth2_http_call_ctx_hdr_set(
	    log, ctx, OAUTH2_HTTP_HDR_CONTENT_TYPE, content_type);
}

bool oauth2_http_call_ctx_bearer_token_set(oauth2_log_t *log,
					   oauth2_http_call_ctx_t *ctx,
					   const char *token)
{
	bool rc = false;
	char *str = NULL;

	if ((ctx == NULL) || (token == NULL))
		goto end;

	str = oauth2_stradd(str, OAUTH2_HTTP_HDR_BEARER, " ", token);

	rc = oauth2_http_call_ctx_hdr_set(log, ctx,
					  OAUTH2_HTTP_HDR_AUTHORIZATION, str);

end:
	if (str)
		oauth2_mem_free(str);

	return rc;
}

bool oauth2_http_call_ctx_basic_auth_set(oauth2_log_t *log,
					 oauth2_http_call_ctx_t *ctx,
					 const char *username,
					 const char *password, bool url_encode)
{
	if (url_encode) {
		ctx->basic_auth_username = oauth2_url_encode(log, username);
		ctx->basic_auth_password = oauth2_url_encode(log, password);
	} else {
		ctx->basic_auth_username = oauth2_strdup(username);
		ctx->basic_auth_password = oauth2_strdup(password);
	}
	return true;
}

static char *_oauth2_http_call_ctx2s(oauth2_log_t *log,
				     oauth2_http_call_ctx_t *ctx)
{
	char *ptr = NULL;

	if (ctx == NULL)
		return NULL;

	if (ctx->to_str)
		oauth2_mem_free(ctx->to_str);

	ctx->to_str = oauth2_strdup("[");
	if (ctx->basic_auth_username)
		ctx->to_str =
		    oauth2_stradd(ctx->to_str, " basic_auth_username",
				  _OAUTH2_STR_EQUAL, ctx->basic_auth_username);
	if (ctx->basic_auth_password)
		ctx->to_str =
		    oauth2_stradd(ctx->to_str, " basic_auth_password",
				  _OAUTH2_STR_EQUAL, ctx->basic_auth_password);
	if (ctx->outgoing_proxy)
		ctx->to_str =
		    oauth2_stradd(ctx->to_str, " outgoing_proxy",
				  _OAUTH2_STR_EQUAL, ctx->outgoing_proxy);
	if (ctx->ca_info)
		ctx->to_str = oauth2_stradd(ctx->to_str, " ca_info",
					    _OAUTH2_STR_EQUAL, ctx->ca_info);
	if (ctx->ssl_cert)
		ctx->to_str = oauth2_stradd(ctx->to_str, " ssl_cert",
					    _OAUTH2_STR_EQUAL, ctx->ssl_cert);
	if (ctx->ssl_key)
		ctx->to_str = oauth2_stradd(ctx->to_str, " ssl_key",
					    _OAUTH2_STR_EQUAL, ctx->ssl_key);

	ptr = oauth2_nv_list2s(log, ctx->hdr);
	if (ptr) {
		ctx->to_str =
		    oauth2_stradd(ctx->to_str, " hdr", _OAUTH2_STR_EQUAL, ptr);
		oauth2_mem_free(ptr);
	}

	ptr = oauth2_nv_list2s(log, ctx->cookie);
	if (ptr) {
		ctx->to_str = oauth2_stradd(ctx->to_str, " cookie",
					    _OAUTH2_STR_EQUAL, ptr);
		oauth2_mem_free(ptr);
	}

	ctx->to_str = oauth2_stradd(ctx->to_str, " ]", NULL, NULL);

	return ctx->to_str;
}

/*
 * encoding
 */

typedef struct _oauth2_http_encode_str_t {
	const char *sep;
	char **str;
} _oauth2_http_encode_str_t;

static bool _oauth2_http_url_encode_list(oauth2_log_t *log, void *rec,
					 const char *key, const char *value)
{
	bool rc = false;
	char *enc_key = NULL, *enc_val = NULL;
	_oauth2_http_encode_str_t *state = (_oauth2_http_encode_str_t *)rec;

	if ((state->str == NULL) || (key == NULL))
		goto end;

	oauth2_debug(log, "processing: %s=%s", key, value);

	enc_key = oauth2_url_encode(log, key);
	enc_val = oauth2_url_encode(log, value);

	*state->str =
	    _oauth2_stradd4(*state->str, *state->str ? state->sep : "", enc_key,
			    _OAUTH2_STR_EQUAL, enc_val);

	rc = true;

end:

	if (enc_key)
		oauth2_mem_free(enc_key);
	if (enc_val)
		oauth2_mem_free(enc_val);

	return rc;
}

static bool _oauth2_http_url_query_encode_param(oauth2_log_t *log, void *rec,
						const char *key,
						const char *value)
{
	_oauth2_http_encode_str_t encode_str = {_OAUTH2_STR_AMP, rec};
	return _oauth2_http_url_encode_list(log, &encode_str, key, value);
}

static bool _oauth2_http_url_encode_cookie(oauth2_log_t *log, void *rec,
					   const char *key, const char *value)
{
	_oauth2_http_encode_str_t encode_str = {_OAUTH2_STR_SEMICOL " ", rec};
	return _oauth2_http_url_encode_list(log, &encode_str, key, value);
}

static char *_oauth2_http_cookies_encode(oauth2_log_t *log,
					 oauth2_nv_list_t *cookies)
{
	char *str = NULL;
	oauth2_nv_list_loop(log, cookies, _oauth2_http_url_encode_cookie, &str);
	return str;
}

char *oauth2_http_url_query_encode(oauth2_log_t *log, const char *url,
				   const oauth2_nv_list_t *params)
{
	char *result = NULL;
	const char *sep = NULL;
	char *encode_str = NULL;

	oauth2_nv_list_loop(log, params, _oauth2_http_url_query_encode_param,
			    &encode_str);

	if (url && encode_str)
		sep = strrchr(url, _OAUTH2_CHAR_QUERY) != NULL
			  ? _OAUTH2_STR_AMP
			  : _OAUTH2_STR_QMARK;

	result = oauth2_stradd(result, url, sep, encode_str);

	oauth2_debug(log, "result=%s", result);

	if (encode_str)
		oauth2_mem_free(encode_str);

	return result;
}

char *oauth2_http_url_form_encode(oauth2_log_t *log,
				  const oauth2_nv_list_t *args)
{
	char *encode_str = NULL;
	oauth2_nv_list_loop(log, args, _oauth2_http_url_query_encode_param,
			    &encode_str);
	oauth2_debug(log, "data=%s", encode_str);
	return encode_str;
}

/*
 * curl
 */

typedef struct oauth2_http_curl_buf_t {
	oauth2_log_t *log;
	char *memory;
	size_t size;
} oauth2_http_curl_buf_t;

#define _OAUTH2_HTTP_CURL_BUF_MAX 1024 * 1024

static size_t oauth2_http_curl_buf_write(void *contents, size_t size,
					 size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb, rc = 0;
	oauth2_http_curl_buf_t *mem = (oauth2_http_curl_buf_t *)userp;

	if (mem->size + realsize > _OAUTH2_HTTP_CURL_BUF_MAX) {
		oauth2_error(mem->log,
			     "HTTP response larger than maximum allowed "
			     "size: current size=%ld, additional "
			     "size=%ld, max=%d",
			     mem->size, realsize, _OAUTH2_HTTP_CURL_BUF_MAX);
		goto end;
	}

	char *newptr = oauth2_mem_alloc(mem->size + realsize + 1);
	if (newptr == NULL) {
		oauth2_error(
		    mem->log,
		    "memory allocation for new buffer of %ld bytes failed",
		    mem->size + realsize + 1);
		goto end;
	}

	memcpy(newptr, mem->memory, mem->size);
	memcpy(&(newptr[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory = newptr;
	mem->memory[mem->size] = 0;

	rc = realsize;

end:

	return rc;
}

static bool _oauth2_http_curl_header_add(oauth2_log_t *log, void *rec,
					 const char *key, const char *value)
{
	bool rc = false;
	char *str = NULL;
	struct curl_slist **h_list = (struct curl_slist **)rec;

	if ((h_list == NULL) || (key == NULL))
		goto end;

	str = _oauth2_stradd4(NULL, key, _OAUTH2_STR_COLON, " ", value);
	if (str == NULL)
		goto end;

	*h_list = curl_slist_append(*h_list, str);

	rc = true;

end:
	if (str)
		oauth2_mem_free(str);

	return rc;
}

bool oauth2_http_call(oauth2_log_t *log, const char *url, const char *data,
		      oauth2_http_call_ctx_t *ctx, char **response,
		      oauth2_http_status_code_t *status_code)
{
	bool rc = false;
	char *str = NULL;
	long response_code = 0;

	char err[CURL_ERROR_SIZE];
	CURL *curl = NULL;
	CURLcode errornum = CURLE_OK;
	struct curl_slist *h_list = NULL;
	oauth2_http_curl_buf_t buf;
	buf.log = log;
	buf.memory = NULL;
	buf.size = 0;

	oauth2_debug(log, "enter: url=%s, data=%s, ctx=%s", url,
		     data ? data : "(null)", _oauth2_http_call_ctx2s(log, ctx));

	if ((url == NULL) || (response == NULL))
		goto end;

	// TODO: this is somewhat shared (at least the initialization of
	// globals) with url-encode/url-decode??
	curl = curl_easy_init();
	if (curl == NULL) {
		oauth2_error(log, "curl_easy_init() error");
		goto end;
	}

	err[0] = 0;

	curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

	if (ctx)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, ctx->timeout);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			 oauth2_http_curl_buf_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buf);

#ifndef LIBCURL_NO_CURLPROTO
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
			 CURLPROTO_HTTP | CURLPROTO_HTTPS);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
			 CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif

	if (ctx) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
				 (ctx->ssl_verify != false ? 1L : 0L));
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
				 (ctx->ssl_verify != false ? 2L : 0L));
	}

	if (ctx && (ctx->ca_info)) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, ctx->ca_info);
	} else {
#ifdef WIN32
		DWORD buflen;
		char *ptr = NULL;
		char *retval = oauth2_mem_alloc(sizeof(TCHAR) * (MAX_PATH + 1));
		retval[0] = '\0';
		buflen = SearchPath(NULL, "curl-ca-bundle.crt", NULL,
				    MAX_PATH + 1, retval, &ptr);
		if (buflen > 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO, retval);
		else
			oauth2_warn(log,
				    "no curl-ca-bundle.crt file found in path");
		oauth2_mem_free(retval);
#endif
	}

	curl_easy_setopt(curl, CURLOPT_USERAGENT, oauth2_package_string());

	if (ctx && ctx->outgoing_proxy)
		curl_easy_setopt(curl, CURLOPT_PROXY, ctx->outgoing_proxy);

	if (ctx && (ctx->basic_auth_username || ctx->basic_auth_password)) {
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		if (ctx->basic_auth_username)
			curl_easy_setopt(curl, CURLOPT_USERNAME,
					 ctx->basic_auth_username);
		if (ctx->basic_auth_password)
			curl_easy_setopt(curl, CURLOPT_PASSWORD,
					 ctx->basic_auth_password);
	}

	if (ctx) {
		if (ctx->ssl_cert != NULL)
			curl_easy_setopt(curl, CURLOPT_SSLCERT, ctx->ssl_cert);
		if (ctx->ssl_key != NULL)
			curl_easy_setopt(curl, CURLOPT_SSLKEY, ctx->ssl_key);
	}

	if (data != NULL) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		curl_easy_setopt(curl, CURLOPT_POST, 1);
	}

	if (ctx)
		oauth2_nv_list_loop(log, ctx->hdr, _oauth2_http_curl_header_add,
				    &h_list);

	if (h_list != NULL)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h_list);

	if (ctx)
		str = _oauth2_http_cookies_encode(log, ctx->cookie);

	if (str) {
		oauth2_debug(log, "passing browser cookies on backend call: %s",
			     str);
		curl_easy_setopt(curl, CURLOPT_COOKIE, str);
		oauth2_mem_free(str);
		str = NULL;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);

	errornum = curl_easy_perform(curl);
	if (errornum != CURLE_OK) {
		oauth2_error(log, "curl_easy_perform() failed on: %s (%s: %s)",
			     url, curl_easy_strerror(errornum),
			     err[0] ? err : "");
		if (errornum == CURLE_OPERATION_TIMEDOUT)
			// 408 Request Timeout
			// 504 Gateway Timeout
			*status_code = 504;
		goto end;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	oauth2_debug(log, "HTTP response code=%ld", response_code);
	if (status_code)
		*status_code = (oauth2_uint_t)response_code;

	*response = oauth2_mem_alloc(buf.size + 1);
	strncpy(*response, buf.memory, buf.size);
	(*response)[buf.size] = '\0';

	rc = true;

end:

	if (buf.memory)
		oauth2_mem_free(buf.memory);
	if (h_list != NULL)
		curl_slist_free_all(h_list);
	curl_easy_cleanup(curl);

	oauth2_debug(log, "leave [%d]: %s", rc,
		     (response && *response) ? *response : "(null)");

	return rc;
}

bool oauth2_http_get(oauth2_log_t *log, const char *url,
		     const oauth2_nv_list_t *params,
		     oauth2_http_call_ctx_t *ctx, char **response,
		     oauth2_http_status_code_t *status_code)
{
	bool rc = false;
	char *query_url = NULL;

	oauth2_debug(log, "enter: %s", url);

	query_url = oauth2_http_url_query_encode(log, url, params);
	rc = oauth2_http_call(log, query_url, NULL, ctx, response, status_code);

	if (query_url)
		oauth2_mem_free(query_url);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_http_post_form(oauth2_log_t *log, const char *url,
			   const oauth2_nv_list_t *params,
			   oauth2_http_call_ctx_t *ctx, char **response,
			   oauth2_http_status_code_t *status_code)
{
	bool rc = false;
	char *data = NULL;

	data = oauth2_http_url_form_encode(log, params);

	oauth2_http_call_ctx_content_type_set(log, ctx,
					      OAUTH2_CONTENT_TYPE_FORM_ENCODED);
	rc = oauth2_http_call(log, url, data, ctx, response, status_code);

	if (data)
		oauth2_mem_free(data);

	return rc;
}

bool oauth2_http_post_json(oauth2_log_t *log, const char *url,
			   const json_t *json, oauth2_http_call_ctx_t *ctx,
			   char **response,
			   oauth2_http_status_code_t *status_code)
{
	bool rc = false;
	char *json_str = NULL;

	if (json)
		json_str = json_dumps(json, JSON_PRESERVE_ORDER | JSON_COMPACT);

	oauth2_http_call_ctx_content_type_set(log, ctx,
					      OAUTH2_CONTENT_TYPE_JSON);
	rc = oauth2_http_call(log, url, json_str, ctx, response, status_code);

	if (json_str)
		oauth2_mem_free(json_str);

	return rc;
}

/*
 * query
 */

static bool _oauth2_http_request_query_parse(oauth2_log_t *log,
					     oauth2_http_request_t *request)
{
	bool rc = false;

	if (request == NULL)
		goto end;

	if (request->_parsed_query != NULL) {
		rc = true;
		goto end;
	}

	request->_parsed_query = oauth2_nv_list_init(log);
	if (request->_parsed_query == NULL)
		goto end;

	rc = _oauth2_nv_list_parse(log, request->query, request->_parsed_query,
				   _OAUTH2_CHAR_AMP, _OAUTH2_CHAR_EQUAL, true,
				   false);

end:

	return rc;
}

bool oauth2_http_request_query_param_add(oauth2_log_t *log,
					 oauth2_http_request_t *request,
					 const char *name, const char *value)
{
	bool rc = false;
	char *query_str = NULL;

	oauth2_debug(log, "enter: %s=%s", name, value);

	if ((request == NULL) || (name == NULL))
		goto end;

	if (_oauth2_http_request_query_parse(log, request) == false)
		goto end;

	if (oauth2_nv_list_add(log, request->_parsed_query, name, value) ==
	    false)
		goto end;

	query_str =
	    oauth2_http_url_query_encode(log, NULL, request->_parsed_query);

	rc = oauth2_http_request_query_set(log, request, query_str);

end:

	if (query_str)
		oauth2_mem_free(query_str);

	oauth2_debug(log, "leave (%d)", rc);

	return rc;
}

const char *oauth2_http_request_query_param_get(oauth2_log_t *log,
						oauth2_http_request_t *request,
						const char *name)
{
	const char *value = NULL;

	oauth2_debug(log, "enter: %s", name);

	if ((request == NULL) || (name == NULL))
		goto end;

	if (_oauth2_http_request_query_parse(log, request) == false)
		goto end;

	value = oauth2_nv_list_get(log, request->_parsed_query, name);

end:

	oauth2_debug(log, "leave: %s=%s", name, value ? value : "(null)");

	return value;
}

bool oauth2_http_request_query_param_unset(oauth2_log_t *log,
					   oauth2_http_request_t *request,
					   const char *name)
{
	bool rc = false;
	char *query_str = NULL;

	oauth2_debug(log, "enter: %s", name);

	if ((request == NULL) || (name == NULL))
		goto end;

	if (_oauth2_http_request_query_parse(log, request) == false) {
		oauth2_error(log, "_oauth2_http_request_query_parse failed");
		goto end;
	}

	if (oauth2_nv_list_unset(log, request->_parsed_query, name) == false) {
		oauth2_error(log, "oauth2_nv_list_unset failed");
		goto end;
	}

	query_str =
	    oauth2_http_url_query_encode(log, NULL, request->_parsed_query);

	rc = oauth2_http_request_query_set(log, request, query_str);

end:

	if (query_str)
		oauth2_mem_free(query_str);

	oauth2_debug(log, "leave: rc=%d", rc);

	return rc;
}

/*
 * cookies
 */

static bool
_oauth2_http_request_get_parsed_cookies(oauth2_log_t *log,
					oauth2_http_request_t *request)
{
	bool rc = false;
	const char *cookies = NULL;

	if (request == NULL)
		goto end;

	if (request->_parsed_cookies != NULL) {
		rc = true;
		goto end;
	}

	request->_parsed_cookies = oauth2_nv_list_init(log);
	if (request->_parsed_cookies == NULL)
		goto end;

	cookies = oauth2_http_request_header_cookie_get(log, request);
	if (cookies == NULL) {
		rc = true;
		goto end;
	}

	rc = _oauth2_nv_list_parse(log, cookies, request->_parsed_cookies,
				   _OAUTH2_CHAR_SEMICOL, _OAUTH2_CHAR_EQUAL,
				   true, false);

end:

	return rc;
}

static bool _oauth2_http_request_set_parsed_cookies_in_header(
    oauth2_log_t *log, oauth2_http_request_t *request)
{
	char *cookies = NULL;

	oauth2_debug(log, "enter");

	cookies = _oauth2_http_cookies_encode(log, request->_parsed_cookies);
	if (cookies == NULL)
		goto end;

	_oauth2_http_request_header_cookie_set(log, request, cookies);

end:

	oauth2_debug(log, "leave: %s", cookies);

	if (cookies)
		oauth2_mem_free(cookies);

	return true;
}

char *oauth2_http_request_cookie_get(oauth2_log_t *log,
				     oauth2_http_request_t *request,
				     const char *name, bool strip)
{
	char *rv = NULL;
	const char *value = NULL;

	oauth2_debug(log, "enter: %s", name);

	if ((request == NULL) || (name == NULL))
		goto end;

	if (_oauth2_http_request_get_parsed_cookies(log, request) == false)
		goto end;

	value = oauth2_nv_list_get(log, request->_parsed_cookies, name);
	if (value == NULL)
		goto end;

	rv = oauth2_strdup(value);

	if (strip == false)
		goto end;

	oauth2_nv_list_unset(log, request->_parsed_cookies, name);
	_oauth2_http_request_set_parsed_cookies_in_header(log, request);

end:

	oauth2_debug(log, "leave: %s=%s", name, rv ? rv : "(null)");

	return rv;
}

bool oauth2_http_request_cookie_set(oauth2_log_t *log,
				    oauth2_http_request_t *request,
				    const char *name, const char *value)
{
	bool rc = false;

	oauth2_debug(log, "enter: %s=%s", name, value);

	if ((request == NULL) || (name == NULL))
		goto end;

	if (_oauth2_http_request_get_parsed_cookies(log, request) == false)
		goto end;

	rc = oauth2_nv_list_set(log, request->_parsed_cookies, name, value);
	if (rc == false)
		goto end;

	rc = _oauth2_http_request_set_parsed_cookies_in_header(log, request);

end:

	oauth2_debug(log, "leave (%d)", rc);

	return rc;
}

/*
 * authentication
 */

bool oauth2_http_auth_client_cert(oauth2_log_t *log, const char *ssl_cert,
				  const char *ssl_key,
				  oauth2_http_call_ctx_t *ctx)
{
	bool rc = false;

	if ((ssl_cert == NULL) || (ssl_key == NULL))
		goto end;

	rc = oauth2_http_call_ctx_ssl_cert_set(log, ctx, ssl_cert);
	if (rc == false)
		goto end;
	rc = oauth2_http_call_ctx_ssl_key_set(log, ctx, ssl_key);

end:

	return rc;
}

bool oauth2_http_auth_basic(oauth2_log_t *log, const char *username,
			    const char *passwd, oauth2_http_call_ctx_t *ctx)
{
	return oauth2_http_call_ctx_basic_auth_set(log, ctx, username, passwd,
						   false);
}

static bool oauth2_http_request_header_contains(
    oauth2_log_t *log, const oauth2_http_request_t *request, const char *name,
    char sepchar, const char *needle)
{
	bool rc = false;
	char *save_input = NULL, *val = NULL;
	const char *value = NULL, *p = NULL;

	if (name == NULL)
		goto end;

	value = oauth2_http_request_header_get(log, request, name);
	if (value == NULL)
		goto end;

	save_input = oauth2_strdup(value);
	p = save_input;

	while (p && *p) {
		val = oauth2_getword(&p, sepchar);
		if (val == NULL)
			break;
		rc = (strncasecmp(val, needle, strlen(needle)) == 0);
		oauth2_mem_free(val);
		if (rc == true)
			break;
	}

end:

	if (save_input)
		oauth2_mem_free(save_input);

	return rc;
}

bool oauth2_http_request_is_xml_http_request(
    oauth2_log_t *log, const oauth2_http_request_t *request)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	if ((oauth2_http_request_header_x_requested_with_get(log, request) !=
	     NULL) &&
	    (strcasecmp(
		 oauth2_http_request_header_x_requested_with_get(log, request),
		 OAUTH2_HTTP_HDR_XML_HTTP_REQUEST) == 0)) {
		rc = true;
		goto end;
	}

	if ((oauth2_http_request_header_contains(
		 log, request, OAUTH2_HTTP_HDR_ACCEPT, _OAUTH2_CHAR_COMMA,
		 OAUTH2_CONTENT_TYPE_TEXT_HTML) == false) &&
	    (oauth2_http_request_header_contains(
		 log, request, OAUTH2_HTTP_HDR_ACCEPT, _OAUTH2_CHAR_COMMA,
		 OAUTH2_CONTENT_TYPE_APP_XHTML_XML) == false) &&
	    (oauth2_http_request_header_contains(
		 log, request, OAUTH2_HTTP_HDR_ACCEPT, _OAUTH2_CHAR_COMMA,
		 OAUTH2_CONTENT_TYPE_ANY) == false)) {
		rc = true;
		goto end;
	}

end:

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

typedef struct oauth2_http_response_t {
	oauth2_nv_list_t *headers;
	oauth2_http_status_code_t status_code;
} oauth2_http_response_t;

oauth2_http_response_t *oauth2_http_response_init(oauth2_log_t *log)
{
	oauth2_http_response_t *response = NULL;

	response = oauth2_mem_alloc(sizeof(oauth2_http_response_t));
	if (response == NULL)
		goto end;

	response->headers = oauth2_nv_list_init(log);
	response->status_code = 0;

end:

	return response;
}

oauth2_http_response_t *
oauth2_http_response_clone(oauth2_log_t *log, oauth2_http_response_t *response)
{
	return NULL;
}

void oauth2_http_response_free(oauth2_log_t *log,
			       oauth2_http_response_t *response)
{
	if (response == NULL)
		goto end;

	if (response->headers)
		oauth2_nv_list_free(log, response->headers);

	oauth2_mem_free(response);

end:

	return;
}

bool oauth2_http_response_headers_set(oauth2_log_t *log,
				      oauth2_http_response_t *response,
				      const oauth2_nv_list_t *hdrs)
{
	return false;
}

oauth2_nv_list_t *
oauth2_http_response_headers_get(oauth2_log_t *log,
				 const oauth2_http_response_t *response)
{
	return response->headers;
}

/*
bool oauth2_http_response_status_code_set(oauth2_log_t *, oauth2_http_response_t
*, const oauth2_http_status_code_t) { return false;
}

oauth2_http_status_code_t  oauth2_http_response_status_code_get(oauth2_log_t *,
const oauth2_http_response_t *) { return 0;
}
*/

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(http, response, status_code,
				      oauth2_http_status_code_t, uint)

bool oauth2_http_response_header_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     const char *name, const char *value)
{
	return oauth2_nv_list_set(log, response->headers, name, value);
}

const char *oauth2_http_response_header_get(oauth2_log_t *log,
					    oauth2_http_response_t *response,
					    const char *name)
{
	return oauth2_nv_list_get(log, response->headers, name);
}

bool oauth2_http_response_cookie_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     const char *name, const char *value)
{
	bool rc = false;
	char *str = NULL;
	oauth2_nv_list_t *cookies = NULL;

	cookies = oauth2_nv_list_init(log);
	oauth2_nv_list_set(log, cookies, name, value);

	str = _oauth2_http_cookies_encode(log, cookies);
	if (str == NULL)
		goto end;

	rc = oauth2_http_response_header_set(log, response,
					     OAUTH2_HTTP_HDR_SET_COOKIE, str);

end:

	if (cookies)
		oauth2_nv_list_free(log, cookies);
	if (str)
		oauth2_mem_free(str);

	return rc;
}

void oauth2_http_response_headers_loop(oauth2_log_t *log,
				       oauth2_http_response_t *response,
				       oauth2_nv_list_loop_cb_t *callback,
				       void *rec)
{
	oauth2_nv_list_loop(log, response->headers, callback, rec);
}
