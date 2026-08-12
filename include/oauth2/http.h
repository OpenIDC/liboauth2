#ifndef _OAUTH2_HTTP_H_
#define _OAUTH2_HTTP_H_

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
 * @file http.h
 * @brief HTTP request/response abstraction and outgoing HTTP client.
 *
 * This is the seam between the server bindings and the core library:
 * a binding translates the hosting server's native request object
 * (Apache's request_rec, NGINX's ngx_http_request_t) into an
 * oauth2_http_request_t and turns the resulting
 * oauth2_http_response_t back into a native response; everything below
 * the bindings operates on these abstract types only. This header also
 * provides the libcurl-based HTTP client used for outgoing calls to
 * OAuth 2.x endpoints.
 */

#include "oauth2/cfg.h"
#include "oauth2/util.h"
#include <jansson.h>

/**
 * @name HTTP header names and values
 * @{
 */
// TODO: can these be http.c internal with the set and get functions available?
#define OAUTH2_HTTP_HDR_X_FORWARDED_PROTO "X-Forwarded-Proto"
#define OAUTH2_HTTP_HDR_X_FORWARDED_PORT "X-Forwarded-Port"
#define OAUTH2_HTTP_HDR_X_FORWARDED_HOST "X-Forwarded-Host"
#define OAUTH2_HTTP_HDR_HOST "Host"
#define OAUTH2_HTTP_HDR_COOKIE "Cookie"
#define OAUTH2_HTTP_HDR_CONTENT_TYPE "Content-Type"
#define OAUTH2_HTTP_HDR_CONTENT_LENGTH "Content-Length"
#define OAUTH2_HTTP_HDR_AUTHORIZATION "Authorization"
#define OAUTH2_HTTP_HDR_X_REQUESTED_WITH "X-Requested-With"
#define OAUTH2_HTTP_HDR_ACCEPT "Accept"
#define OAUTH2_HTTP_HDR_LOCATION "Location"
#define OAUTH2_HTTP_HDR_SET_COOKIE "Set-Cookie"

#define OAUTH2_HTTP_HDR_BEARER "Bearer"
#define OAUTH2_HTTP_HDR_BASIC "Basic"

#define OAUTH2_HTTP_HDR_REALM "realm"

#define OAUTH2_HTTP_HDR_WWW_AUTHENTICATE "WWW-Authenticate"
#define OAUTH2_HTTP_HDR_XML_HTTP_REQUEST "XMLHttpRequest"

#define OAUTH2_TLS_CERT_VAR_NAME "SSL_CLIENT_CERT"
/** @} */

/**
 * @name Content types
 * @{
 */
#define OAUTH2_CONTENT_TYPE_FORM_ENCODED "application/x-www-form-urlencoded"
#define OAUTH2_CONTENT_TYPE_JSON "application/json"
#define OAUTH2_CONTENT_TYPE_TEXT_HTML "text/html"
#define OAUTH2_CONTENT_TYPE_APP_XHTML_XML "application/xhtml+xml"
#define OAUTH2_CONTENT_TYPE_ANY "*/*"
/** @} */

/**
 * @name Protocol constants
 * @{
 */
#define OAUTH2_HTTP_SCHEME_HTTP "http"
#define OAUTH2_HTTP_SCHEME_HTTPS "https"

typedef enum {
	OAUTH2_HTTP_METHOD_UNKNOWN,
	OAUTH2_HTTP_METHOD_GET,
	OAUTH2_HTTP_METHOD_PUT,
	OAUTH2_HTTP_METHOD_POST,
	OAUTH2_HTTP_METHOD_DELETE,
	OAUTH2_HTTP_METHOD_CONNECT,
	OAUTH2_HTTP_METHOD_OPTIONS
} oauth2_http_method_t;

typedef oauth2_uint_t oauth2_http_status_code_t;
/** @} */

/**
 * @name Incoming HTTP request
 * oauth2_http_request_t represents an incoming HTTP request,
 * independent of the hosting server. A server binding creates one per
 * native request and populates: the native URL scheme on which the
 * request was received (i.e. without taking forwarding headers into
 * account), the configured server hostname, the native port, the path,
 * the HTTP method, the query string, and each incoming header. The
 * oauth2_http_request_url_..._get() functions derive the externally
 * visible URL from these, taking the X-Forwarded-Proto,
 * X-Forwarded-Host, X-Forwarded-Port and Host headers into account
 * when present. The request context is a name/value list for
 * additional per-request data provided by the binding, such as the
 * TLS client certificate under OAUTH2_TLS_CERT_VAR_NAME.
 * @{
 */
OAUTH2_TYPE_DECLARE(http, request)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, scheme, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, hostname, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, path, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, method, oauth2_http_method_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, query, char *)
const char *oauth2_http_request_method_get_str(oauth2_log_t *,
					       oauth2_http_request_t *);
bool oauth2_http_request_context_set(oauth2_log_t *log,
				     oauth2_http_request_t *request,
				     const char *name, const char *value);
const char *oauth2_http_request_context_get(
    oauth2_log_t *log, const oauth2_http_request_t *request, const char *name);
/** @} */

/**
 * @name Outgoing HTTP response
 * oauth2_http_response_t represents the HTTP response that the core
 * hands back to the server binding to be delivered to the user agent:
 * a status code plus headers (e.g. Location and Set-Cookie); the
 * binding translates it into its native response object.
 * @{
 */
OAUTH2_TYPE_DECLARE(http, response)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, response, headers, oauth2_nv_list_t *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, response, status_code,
				   oauth2_http_status_code_t)

bool oauth2_http_response_header_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     const char *name, const char *value);
const char *
oauth2_http_response_header_get(oauth2_log_t *log,
				const oauth2_http_response_t *response,
				const char *name);
const char *oauth2_http_response_header_set_cookie_prefix_get(
    oauth2_log_t *log, oauth2_http_response_t *response, const char *prefix);
bool oauth2_http_response_cookie_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     const char *name, const char *value,
				     const char *path, const bool is_secure,
				     oauth2_time_t max_age);
void oauth2_http_response_headers_loop(oauth2_log_t *log,
				       const oauth2_http_response_t *response,
				       oauth2_nv_list_loop_cb_t *callback,
				       void *rec);
/** @} */

// typedef bool (*oauth2_http_read_post_callback_t)(oauth2_log_t *log,
// oauth2_http_request_t *request, char **data);

/**
 * @name Request URL
 * The ..._url_..._get() functions return the currently accessed URL
 * (scheme://host[:port], the path variant, and the full URL including
 * the query string) as derived from the populated request members and
 * the forwarding headers. All return a newly allocated string, to be
 * released with oauth2_mem_free(), or NULL on error.
 * @{
 */
bool oauth2_http_request_port_set(oauth2_log_t *log, oauth2_http_request_t *r,
				  unsigned long port);
char *oauth2_http_request_port_get(oauth2_log_t *log,
				   const oauth2_http_request_t *r);

char *oauth2_http_request_url_base_get(oauth2_log_t *log,
				       const oauth2_http_request_t *r);
char *oauth2_http_request_url_path_get(oauth2_log_t *log,
				       const oauth2_http_request_t *request);
char *oauth2_http_request_url_get(oauth2_log_t *log,
				  const oauth2_http_request_t *r);
/** @} */

/**
 * @name Request headers
 * Set/unset/add/get incoming request headers, iterate over them, and
 * convenience getters for common headers. The _get functions return a
 * pointer into the request's own header list.
 * @{
 */

OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, request, header)

void oauth2_http_request_headers_loop(oauth2_log_t *log,
				      oauth2_http_request_t *request,
				      oauth2_nv_list_loop_cb_t *callback,
				      void *rec);

const char *
oauth2_http_request_header_content_type_get(oauth2_log_t *log,
					    const oauth2_http_request_t *r);
const char *
oauth2_http_request_header_cookie_get(oauth2_log_t *log,
				      const oauth2_http_request_t *r);
const char *
oauth2_http_request_header_content_length_get(oauth2_log_t *log,
					      const oauth2_http_request_t *r);
bool oauth2_http_request_header_content_length_set(oauth2_log_t *log,
						   oauth2_http_request_t *r,
						   size_t len);
const char *
oauth2_http_request_header_x_requested_with_get(oauth2_log_t *log,
						const oauth2_http_request_t *r);
const char *
oauth2_http_request_header_accept_get(oauth2_log_t *log,
				      const oauth2_http_request_t *request);

/** @brief Check the X-Requested-With header for "XMLHttpRequest". */
bool oauth2_http_request_is_xml_http_request(
    oauth2_log_t *log, const oauth2_http_request_t *request);
/** @brief Check whether the request was received over https. */
bool oauth2_http_request_is_secure(oauth2_log_t *log,
				   const oauth2_http_request_t *request);
/** @} */

/**
 * @name Query and form parameters
 * Encode name/value lists into query strings or form-encoded data and
 * access/modify the query parameters of an incoming request.
 * @{
 */

char *oauth2_http_url_query_encode(oauth2_log_t *log, const char *url,
				   const oauth2_nv_list_t *args);
char *oauth2_http_url_form_encode(oauth2_log_t *log,
				  const oauth2_nv_list_t *args);
bool oauth2_http_request_query_param_add(oauth2_log_t *log,
					 oauth2_http_request_t *request,
					 const char *name, const char *value);
const char *oauth2_http_request_query_param_get(oauth2_log_t *log,
						oauth2_http_request_t *request,
						const char *name);
bool oauth2_http_request_query_param_unset(oauth2_log_t *log,
					   oauth2_http_request_t *request,
					   const char *name);
/** @} */

/**
 * @name Outgoing call context
 * oauth2_http_call_ctx_t holds the per-call settings for an outgoing
 * HTTP request: a bearer token, content type, outgoing proxy, CA
 * bundle, TLS client certificate/key, timeout and retry behaviour,
 * TLS server certificate verification, plus cookies and headers to
 * send and basic authentication credentials.
 * @{
 */

OAUTH2_TYPE_DECLARE(http, call_ctx)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, bearer_token, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, content_type, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, outgoing_proxy, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ca_info, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_cert, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_key, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, timeout, int)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, retries, int)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, retry_interval, int)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_verify, bool)
OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, call_ctx, cookie)
OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, call_ctx, hdr)
bool oauth2_http_call_ctx_basic_auth_set(oauth2_log_t *log,
					 oauth2_http_call_ctx_t *ctx,
					 const char *username,
					 const char *password, bool url_encode);
/** @} */

/**
 * @name Outgoing calls
 * Execute an outgoing HTTP call. On success the response body is
 * returned in @p response as a newly allocated string, to be released
 * with oauth2_mem_free(), and the HTTP status code in @p status_code
 * (both may be NULL when not needed). oauth2_http_call() is the
 * generic form: it POSTs @p data when non-NULL (with the content type
 * set on the call context) and performs a plain GET otherwise; the
 * _get/_post_form/_post_json variants encode a parameter list or JSON
 * object accordingly.
 * @{
 */

bool oauth2_http_call(oauth2_log_t *log, const char *url, const char *data,
		      oauth2_http_call_ctx_t *ctx, char **response,
		      oauth2_http_status_code_t *status_code);
bool oauth2_http_get(oauth2_log_t *log, const char *url,
		     const oauth2_nv_list_t *params,
		     oauth2_http_call_ctx_t *ctx, char **response,
		     oauth2_http_status_code_t *status_code);
bool oauth2_http_post_form(oauth2_log_t *log, const char *url,
			   const oauth2_nv_list_t *params,
			   oauth2_http_call_ctx_t *ctx, char **response,
			   oauth2_http_status_code_t *status_code);
bool oauth2_http_post_json(oauth2_log_t *log, const char *url,
			   const json_t *json, oauth2_http_call_ctx_t *ctx,
			   char **response,
			   oauth2_http_status_code_t *status_code);
/** @} */

/**
 * @name Request cookies
 * @{
 */

/**
 * @brief Get a cookie value from an incoming request.
 *
 * @param log   the log handle to use
 * @param r     the incoming HTTP request
 * @param name  the name of the cookie
 * @param strip when true, the cookie is removed from the request's
 *              Cookie header so it is not passed on to the target
 *              application
 * @return the cookie value as a newly allocated string, to be released
 *         with oauth2_mem_free(), or NULL when not found
 */
char *oauth2_http_request_cookie_get(oauth2_log_t *log,
				     oauth2_http_request_t *r, const char *name,
				     bool strip);
bool oauth2_http_request_cookie_set(oauth2_log_t *log, oauth2_http_request_t *r,
				    const char *name, const char *value);
/** @} */

/**
 * @name Outgoing call authentication
 * Set a TLS client certificate/key or basic authentication credentials
 * on an outgoing call context.
 * @{
 */

bool oauth2_http_auth_client_cert(oauth2_log_t *log, const char *ssl_cert,
				  const char *ssl_key,
				  oauth2_http_call_ctx_t *ctx);
bool oauth2_http_auth_basic(oauth2_log_t *log, const char *username,
			    const char *passwd, oauth2_http_call_ctx_t *ctx);
/** @} */

#endif /* _OAUTH2_HTTP_H_ */
