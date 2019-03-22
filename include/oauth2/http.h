#ifndef _OAUTH2_HTTP_H_
#define _OAUTH2_HTTP_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone IT BV - www.zmartzone.eu
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

#include "oauth2/cfg.h"
#include "oauth2/util.h"
#include <jansson.h>

/*
 * header names
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

#define OAUTH2_HTTP_HDR_BEARER "Bearer"
#define OAUTH2_HTTP_HDR_BASIC "Basic"

#define OAUTH2_HTTP_HDR_REALM "realm"

#define OAUTH2_HTTP_HDR_WWW_AUTHENTICATE "WWW-Authenticate"

/*
 * content type
 */
#define OAUTH2_CONTENT_TYPE_FORM_ENCODED "application/x-www-form-urlencoded"
#define OAUTH2_CONTENT_TYPE_JSON "application/json"

/*
 * protocol
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

/*
 * TODO: make sure the caller calls:
 *       1. oauth2_http_request_scheme_set to set the "native" URL scheme on
 * which the request was received i.e. without taking into account headers
 *       2. oauth2_http_request_hostname_set to set the configured server
 * hostname
 *       3. oauth2_http_request_port_set to set the "hative" port on which the
 *       request was received
 *       4. oauth2_http_request_path_set for the path that is accessed
 *       5. oauth2_http_request_method_set for the HTTP method used
 *       6. oauth2_http_request_query_set for the query string
 *       7. oauth2_http_request_hdr_in_set for each incoming header
 */
OAUTH2_TYPE_DECLARE(http, request)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, scheme, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, hostname, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, path, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, method, oauth2_http_method_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, query, char *)

// typedef bool (*oauth2_http_read_post_callback_t)(oauth2_log_t *log,
// oauth2_http_request_t *request, char **data);

bool oauth2_http_request_port_set(oauth2_log_t *log, oauth2_http_request_t *r,
				  unsigned long port);
char *oauth2_http_request_port_get(oauth2_log_t *log,
				   const oauth2_http_request_t *r);

/*
 * currently accessed url functions
 */
char *oauth2_http_request_url_base_get(oauth2_log_t *log,
				       const oauth2_http_request_t *r);
char *oauth2_http_request_url_get(oauth2_log_t *log,
				  const oauth2_http_request_t *r);

/*
 * request header functions
 */

OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, request, hdr_in)

void oauth2_http_request_hdr_in_loop(oauth2_log_t *log,
				     oauth2_http_request_t *request,
				     oauth2_nv_list_loop_cb_t *callback,
				     void *rec);

const char *oauth2_http_hdr_in_content_type_get(oauth2_log_t *log,
						const oauth2_http_request_t *r);
const char *oauth2_http_hdr_in_cookie_get(oauth2_log_t *log,
					  const oauth2_http_request_t *r);
const char *
oauth2_http_hdr_in_content_length_get(oauth2_log_t *log,
				      const oauth2_http_request_t *r);
bool oauth2_http_hdr_in_content_length_set(oauth2_log_t *log,
					   oauth2_http_request_t *r,
					   size_t len);

/*
 * request args functions
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

/*
 * http call context object
 */

OAUTH2_TYPE_DECLARE(http, call_ctx)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, bearer_token, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, content_type, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, outgoing_proxy, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ca_info, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_cert, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_key, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, timeout, int)
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_verify, bool)
OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, call_ctx, cookie)
OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, call_ctx, hdr)
bool oauth2_http_call_ctx_basic_auth_set(oauth2_log_t *log,
					 oauth2_http_call_ctx_t *ctx,
					 const char *username,
					 const char *password, bool url_encode);

/*
 * http call functions
 */

bool oauth2_http_call(oauth2_log_t *log, const char *url, const char *data,
		      oauth2_http_call_ctx_t *ctx, char **response,
		      oauth2_uint_t *status_code);
bool oauth2_http_get(oauth2_log_t *log, const char *url,
		     const oauth2_nv_list_t *params,
		     oauth2_http_call_ctx_t *ctx, char **response,
		     oauth2_uint_t *status_code);
bool oauth2_http_post_form(oauth2_log_t *log, const char *url,
			   const oauth2_nv_list_t *params,
			   oauth2_http_call_ctx_t *ctx, char **response,
			   oauth2_uint_t *status_code);
bool oauth2_http_post_json(oauth2_log_t *log, const char *url,
			   const json_t *json, oauth2_http_call_ctx_t *ctx,
			   char **response, oauth2_uint_t *status_code);

/*
 * http cookie functions
 */

char *oauth2_http_request_cookie_get(oauth2_log_t *log,
				     oauth2_http_request_t *r, const char *name,
				     bool strip);
bool oauth2_http_request_cookie_set(oauth2_log_t *log, oauth2_http_request_t *r,
				    const char *name, const char *value);

/*
 * http auth
 */

bool oauth2_http_auth_client_cert(oauth2_log_t *log, const char *ssl_cert,
				  const char *ssl_key,
				  oauth2_http_call_ctx_t *ctx);
bool oauth2_http_auth_basic(oauth2_log_t *log, const char *username,
			    const char *passwd, oauth2_http_call_ctx_t *ctx);

#endif /* _OAUTH2_HTTP_H_ */
