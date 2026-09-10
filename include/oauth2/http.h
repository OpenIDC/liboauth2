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
 * The headers the library reads from incoming requests and writes to
 * outgoing calls and responses, and the values it recognizes in them.
 * @{
 */
// TODO: can these be http.c internal with the set and get functions available?
/** @brief The scheme a reverse proxy received the request on. */
#define OAUTH2_HTTP_HDR_X_FORWARDED_PROTO "X-Forwarded-Proto"
/** @brief The port a reverse proxy received the request on. */
#define OAUTH2_HTTP_HDR_X_FORWARDED_PORT "X-Forwarded-Port"
/** @brief The host, with optional port, a reverse proxy received the
 *         request for. */
#define OAUTH2_HTTP_HDR_X_FORWARDED_HOST "X-Forwarded-Host"
/** @brief The host, with optional port, the user agent addressed. */
#define OAUTH2_HTTP_HDR_HOST "Host"
/** @brief The cookies sent by the user agent. */
#define OAUTH2_HTTP_HDR_COOKIE "Cookie"
/** @brief The media type of a request or response body. */
#define OAUTH2_HTTP_HDR_CONTENT_TYPE "Content-Type"
/** @brief The size of a request or response body in bytes. */
#define OAUTH2_HTTP_HDR_CONTENT_LENGTH "Content-Length"
/** @brief The credentials a client presents. */
#define OAUTH2_HTTP_HDR_AUTHORIZATION "Authorization"
/** @brief Set by JavaScript frameworks on the requests they issue. */
#define OAUTH2_HTTP_HDR_X_REQUESTED_WITH "X-Requested-With"
/** @brief The media types the user agent accepts in a response. */
#define OAUTH2_HTTP_HDR_ACCEPT "Accept"
/** @brief The target of a redirect response. */
#define OAUTH2_HTTP_HDR_LOCATION "Location"
/** @brief A cookie a response sets on the user agent. */
#define OAUTH2_HTTP_HDR_SET_COOKIE "Set-Cookie"

/** @brief The Authorization scheme carrying a bearer token (RFC 6750). */
#define OAUTH2_HTTP_HDR_BEARER "Bearer"
/** @brief The Authorization scheme carrying a username and password
 *         (RFC 7617). */
#define OAUTH2_HTTP_HDR_BASIC "Basic"

/** @brief The realm attribute of a WWW-Authenticate challenge. */
#define OAUTH2_HTTP_HDR_REALM "realm"

/** @brief The challenge a 401 response carries. */
#define OAUTH2_HTTP_HDR_WWW_AUTHENTICATE "WWW-Authenticate"
/** @brief The X-Requested-With value that identifies an AJAX request. */
#define OAUTH2_HTTP_HDR_XML_HTTP_REQUEST "XMLHttpRequest"

/**
 * @brief The request context key (oauth2_http_request_context_set())
 *        under which a server binding stores the PEM-encoded TLS
 *        client certificate of the connection, for the mTLS-bound
 *        token check in oauth2_token_verify() (oauth2.h).
 */
#define OAUTH2_TLS_CERT_VAR_NAME "SSL_CLIENT_CERT"
/** @} */

/**
 * @name Content types
 * @{
 */
/** @brief HTML form data: token endpoint requests, POSTed tokens. */
#define OAUTH2_CONTENT_TYPE_FORM_ENCODED "application/x-www-form-urlencoded"
/** @brief JSON documents: endpoint responses, JSON POSTs. */
#define OAUTH2_CONTENT_TYPE_JSON "application/json"
/** @brief HTML pages; a user agent not accepting them is treated as a
 *         script, see oauth2_http_request_is_xml_http_request(). */
#define OAUTH2_CONTENT_TYPE_TEXT_HTML "text/html"
/** @brief XHTML pages, accepted like text/html. */
#define OAUTH2_CONTENT_TYPE_APP_XHTML_XML "application/xhtml+xml"
/** @brief The Accept wildcard matching any media type. */
#define OAUTH2_CONTENT_TYPE_ANY "*/*"
/** @} */

/**
 * @name Protocol constants
 * @{
 */
/** @brief The URL scheme of plain HTTP. */
#define OAUTH2_HTTP_SCHEME_HTTP "http"
/** @brief The URL scheme of HTTP over TLS. */
#define OAUTH2_HTTP_SCHEME_HTTPS "https"

/** @brief The method of an incoming HTTP request. */
typedef enum {
	OAUTH2_HTTP_METHOD_UNKNOWN, /**< not set, or none of the below */
	OAUTH2_HTTP_METHOD_GET,	    /**< GET */
	OAUTH2_HTTP_METHOD_PUT,	    /**< PUT */
	OAUTH2_HTTP_METHOD_POST,    /**< POST */
	OAUTH2_HTTP_METHOD_DELETE,  /**< DELETE */
	OAUTH2_HTTP_METHOD_CONNECT, /**< CONNECT */
	OAUTH2_HTTP_METHOD_OPTIONS  /**< OPTIONS */
} oauth2_http_method_t;

/** @brief An HTTP status code, e.g. 200, 302 or 401. */
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
 *
 * The member setters copy the value and reject NULL; the generated
 * getters return the member as stored and abort on a NULL request,
 * whereas the hand-written scheme and hostname getters derive the
 * externally visible values, see below.
 * @{
 */
/**
 * @brief Opaque incoming request with its init and free functions; the
 *        _clone function the declaration macro names is not
 *        implemented.
 */
OAUTH2_TYPE_DECLARE(http, request)
/**
 * @brief The native URL scheme, "http" or "https", the request was
 *        received on.
 *
 * The getter is hand-written: it returns the left-most value of the
 * X-Forwarded-Proto header when present and the native scheme
 * otherwise, falling back to "https" with a warning when the result is
 * neither "http" nor "https", as a newly allocated string to be
 * released with oauth2_mem_free(), or NULL when the request is NULL.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, scheme, char *)
/**
 * @brief The configured hostname of the server.
 *
 * The getter is hand-written: it prefers the left-most value of the
 * X-Forwarded-Host header, then the Host header, both with any ":port"
 * suffix removed, over the configured hostname, and returns a newly
 * allocated string to be released with oauth2_mem_free(), or NULL when
 * none of them is set.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, hostname, char *)
/** @brief The path of the request URL, without the query string. */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, path, char *)
/** @brief The HTTP method; OAUTH2_HTTP_METHOD_UNKNOWN until set. */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, method, oauth2_http_method_t)
/**
 * @brief The raw query string, without the leading "?"; the
 *        ..._query_param_...() functions parse and rewrite it.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, request, query, char *)
/**
 * @brief Get the request method as its uppercase name, e.g. "GET".
 * @return a static string, or NULL for OAUTH2_HTTP_METHOD_UNKNOWN
 */
const char *oauth2_http_request_method_get_str(oauth2_log_t *,
					       oauth2_http_request_t *);
/**
 * @brief Store a value in the request context.
 *
 * The context is a case-sensitive name/value list, separate from the
 * headers, in which a server binding passes per-request data that has
 * no place in the HTTP request itself, such as the TLS client
 * certificate under OAUTH2_TLS_CERT_VAR_NAME.
 *
 * @param log     the log handle to use
 * @param request the request to store into
 * @param name    the name to store the value under, replacing an
 *                existing value of that name
 * @param value   the value, copied into the request; may be NULL
 * @return true when stored, false when request or name is NULL
 */
bool oauth2_http_request_context_set(oauth2_log_t *log,
				     oauth2_http_request_t *request,
				     const char *name, const char *value);
/**
 * @brief Look up a value in the request context.
 * @return a borrowed pointer to the value, or NULL when not set
 */
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
/**
 * @brief Opaque outgoing response with its init, clone and free
 *        functions.
 */
OAUTH2_TYPE_DECLARE(http, response)
/**
 * @brief The response headers as a name/value list owned by the
 *        response. The setter is not implemented and returns false:
 *        use oauth2_http_response_header_set() and
 *        oauth2_http_response_cookie_set() instead.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, response, headers, oauth2_nv_list_t *)
/** @brief The HTTP status code to respond with; 0 until set. */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(http, response, status_code,
				   oauth2_http_status_code_t)

/**
 * @brief Set a response header, replacing an existing header of that
 *        name (matched case-sensitively) or adding it when absent.
 * @return true when set, false when the name is NULL
 */
bool oauth2_http_response_header_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     const char *name, const char *value);
/**
 * @brief Get a response header.
 * @return a borrowed pointer into the response's header list, or NULL
 *         when not set
 */
const char *
oauth2_http_response_header_get(oauth2_log_t *log,
				const oauth2_http_response_t *response,
				const char *name);
/**
 * @brief Find the first Set-Cookie header whose value starts with a
 *        prefix, typically "name=" to find the cookie of that name.
 * @return a borrowed pointer to the complete Set-Cookie value, or NULL
 *         when none matches
 */
const char *oauth2_http_response_header_set_cookie_prefix_get(
    oauth2_log_t *log, oauth2_http_response_t *response, const char *prefix);
/**
 * @brief Add a Set-Cookie header to the response.
 *
 * Each cookie set on a response gets its own Set-Cookie header; the
 * name and value are URL-encoded.
 *
 * @param log       the log handle to use
 * @param response  the response to add the header to
 * @param name      the name of the cookie
 * @param value     the value of the cookie, or NULL to clear the
 *                  cookie on the user agent with an empty value that
 *                  expires on the epoch with Max-Age=0
 * @param path      the Path attribute, or NULL to omit it
 * @param is_secure when true, the HttpOnly, Secure and SameSite=None
 *                  attributes are added
 * @param max_age   the Max-Age attribute in seconds, or
 *                  OAUTH2_CFG_TIME_UNSET (cfg.h) to omit it; not used
 *                  when clearing
 * @return true when added, false on error
 */
bool oauth2_http_response_cookie_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     const char *name, const char *value,
				     const char *path, const bool is_secure,
				     oauth2_time_t max_age);
/**
 * @brief Iterate over the response headers in the order they were set.
 * @param log      the log handle to use
 * @param response the response whose headers to iterate over
 * @param callback called for each header with its name and value;
 *                 returning false stops the iteration
 * @param rec      passed to the callback unchanged
 */
void oauth2_http_response_headers_loop(oauth2_log_t *log,
				       const oauth2_http_response_t *response,
				       oauth2_nv_list_loop_cb_t *callback,
				       void *rec);
/** @} */

// typedef bool (*oauth2_http_read_post_callback_t)(oauth2_log_t *log,
// oauth2_http_request_t *request, char **data);

/**
 * @name Request URL
 * The ..._url_..._get() functions return the externally visible URL of
 * the request - scheme://host[:port], that plus the path, and the full
 * URL including the query string - as derived from the populated
 * request members and the forwarding headers. All return a newly
 * allocated string, to be released with oauth2_mem_free(), or NULL on
 * error.
 * @{
 */
/**
 * @brief Set the native port the request was received on; 0 means
 *        that there is none, e.g. for a Unix domain socket.
 * @return true, false when the request is NULL
 */
bool oauth2_http_request_port_set(oauth2_log_t *log, oauth2_http_request_t *r,
				  unsigned long port);
/**
 * @brief Get the port of the externally visible URL.
 *
 * Takes, in this order, the left-most X-Forwarded-Port value, the
 * ":port" suffix of the left-most X-Forwarded-Host value, the ":port"
 * suffix of the Host header, no port at all when an X-Forwarded-Proto
 * header is present (the forwarded scheme's default port applies), and
 * otherwise the native port unless it is the default port of the
 * scheme (443 for https, 80 for http).
 *
 * @return the port as a newly allocated string, to be released with
 *         oauth2_mem_free(), or NULL when the URL needs no explicit
 *         port
 */
char *oauth2_http_request_port_get(oauth2_log_t *log,
				   const oauth2_http_request_t *r);

/** @brief Get "scheme://host[:port]" of the request. */
char *oauth2_http_request_url_base_get(oauth2_log_t *log,
				       const oauth2_http_request_t *r);
/** @brief Get "scheme://host[:port]/path" of the request. */
char *oauth2_http_request_url_path_get(oauth2_log_t *log,
				       const oauth2_http_request_t *request);
/**
 * @brief Get the full request URL, "?query" included when a query
 *        string is set.
 */
char *oauth2_http_request_url_get(oauth2_log_t *log,
				  const oauth2_http_request_t *r);
/** @} */

/**
 * @name Request headers
 * Set/unset/add/get incoming request headers, iterate over them, and
 * convenience getters for common headers. Header names are matched
 * case-insensitively; the _get functions return a pointer into the
 * request's own header list, or NULL when the header is absent.
 * @{
 */

/**
 * @brief The incoming headers: oauth2_http_request_header_set()
 *        replaces the first header of that name, adding it when
 *        absent, _add() appends another one, _unset() removes the
 *        first one and _get() returns the value of the first one. The
 *        set and add functions replace every line feed in the value by
 *        a space, so a value cannot inject headers when the request is
 *        passed on, and return false when the request or the name is
 *        NULL.
 */
OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, request, header)

/**
 * @brief Iterate over the request headers in the order they were set.
 * @param log      the log handle to use
 * @param request  the request whose headers to iterate over
 * @param callback called for each header with its name and value;
 *                 returning false stops the iteration
 * @param rec      passed to the callback unchanged
 */
void oauth2_http_request_headers_loop(oauth2_log_t *log,
				      oauth2_http_request_t *request,
				      oauth2_nv_list_loop_cb_t *callback,
				      void *rec);

/** @brief Get the Content-Type header. */
const char *
oauth2_http_request_header_content_type_get(oauth2_log_t *log,
					    const oauth2_http_request_t *r);
/**
 * @brief Get the raw Cookie header; see oauth2_http_request_cookie_get()
 *        for a single cookie.
 */
const char *
oauth2_http_request_header_cookie_get(oauth2_log_t *log,
				      const oauth2_http_request_t *r);
/** @brief Get the Content-Length header. */
const char *
oauth2_http_request_header_content_length_get(oauth2_log_t *log,
					      const oauth2_http_request_t *r);
/**
 * @brief Set the Content-Length header from a byte count, e.g. after
 *        rewriting the request body.
 */
bool oauth2_http_request_header_content_length_set(oauth2_log_t *log,
						   oauth2_http_request_t *r,
						   size_t len);
/** @brief Get the X-Requested-With header. */
const char *
oauth2_http_request_header_x_requested_with_get(oauth2_log_t *log,
						const oauth2_http_request_t *r);
/** @brief Get the Accept header. */
const char *
oauth2_http_request_header_accept_get(oauth2_log_t *log,
				      const oauth2_http_request_t *request);

/**
 * @brief Check whether a script rather than a navigating user issued
 *        the request, in which case a redirect to the authorization
 *        server is pointless.
 *
 * True when the X-Requested-With header equals "XMLHttpRequest"
 * (case-insensitively), or when the Accept header lists neither
 * text/html, application/xhtml+xml nor the any-type wildcard
 * (OAUTH2_CONTENT_TYPE_ANY).
 */
bool oauth2_http_request_is_xml_http_request(
    oauth2_log_t *log, const oauth2_http_request_t *request);
/**
 * @brief Check whether the request was received over https, taking the
 *        X-Forwarded-Proto header into account like
 *        oauth2_http_request_scheme_get() does; false for a NULL
 *        request.
 */
bool oauth2_http_request_is_secure(oauth2_log_t *log,
				   const oauth2_http_request_t *request);
/** @} */

/**
 * @name Query and form parameters
 * Encode name/value lists into query strings or form-encoded data and
 * access/modify the query parameters of an incoming request. The
 * request's query string is parsed on first access - split on "&" and
 * "=", trimmed and URL-decoded - and re-encoded into the query member
 * after a modification.
 * @{
 */

/**
 * @brief Append URL-encoded parameters to a URL.
 *
 * @param log  the log handle to use
 * @param url  the URL to append to, "?" or "&" is inserted depending
 *             on whether it already carries a query string; NULL to
 *             get the encoded parameters alone
 * @param args the parameters, names and values URL-encoded and joined
 *             with "&"; may be NULL or empty
 * @return the result as a newly allocated string, to be released with
 *         oauth2_mem_free(), or NULL on error
 */
char *oauth2_http_url_query_encode(oauth2_log_t *log, const char *url,
				   const oauth2_nv_list_t *args);
/**
 * @brief Encode parameters as application/x-www-form-urlencoded data.
 * @return the encoded data as a newly allocated string, to be released
 *         with oauth2_mem_free(), or NULL when args is NULL or empty
 */
char *oauth2_http_url_form_encode(oauth2_log_t *log,
				  const oauth2_nv_list_t *args);
/**
 * @brief Add a query parameter to the request, keeping existing ones
 *        of the same name.
 * @return true when the query string was updated, false on error
 */
bool oauth2_http_request_query_param_add(oauth2_log_t *log,
					 oauth2_http_request_t *request,
					 const char *name, const char *value);
/**
 * @brief Get a query parameter of the request.
 * @return a borrowed pointer to the URL-decoded value of the first
 *         parameter of that name, valid until the query is modified,
 *         or NULL when absent
 */
const char *oauth2_http_request_query_param_get(oauth2_log_t *log,
						oauth2_http_request_t *request,
						const char *name);
/**
 * @brief Remove the first query parameter of a name from the request,
 *        e.g. to strip an access token before passing the request on.
 * @return true when the query string was updated (also when there was
 *         no such parameter), false on error
 */
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
 * send and basic authentication credentials. A new context has a
 * timeout of 15 seconds, 1 retry after an interval of 300
 * milliseconds and TLS verification enabled.
 * @{
 */

/**
 * @brief Opaque per-call settings with their init and free functions;
 *        the _clone function the declaration macro names is not
 *        implemented.
 */
OAUTH2_TYPE_DECLARE(http, call_ctx)
/**
 * @brief Send the token in an "Authorization: Bearer" header; NULL is
 *        rejected.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, bearer_token, char *)
/** @brief The Content-Type header to send along with a POSTed body. */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, content_type, char *)
/** @brief The proxy to route the call through, as a libcurl proxy
 *         URL. */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, outgoing_proxy, char *)
/**
 * @brief The CA bundle file to verify the server certificate against;
 *        libcurl's default bundle when unset.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ca_info, char *)
/** @brief The TLS client certificate file to present. */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_cert, char *)
/** @brief The private key file belonging to the client certificate. */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_key, char *)
/** @brief The total time allowed for one attempt, in seconds. */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, timeout, int)
/**
 * @brief How often to retry an attempt that failed for a reason other
 *        than a timeout.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, retries, int)
/** @brief The time to wait before a retry, in milliseconds. */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, retry_interval, int)
/** @brief Whether to verify the server's TLS certificate and hostname. */
OAUTH2_TYPE_DECLARE_MEMBER_SET(http, call_ctx, ssl_verify, bool)
/**
 * @brief Cookies to send with the call in a Cookie header, names and
 *        values URL-encoded and joined with "; ".
 */
OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, call_ctx, cookie)
/**
 * @brief Headers to send with the call, names matched
 *        case-insensitively; the bearer token and content type are
 *        stored here as well.
 */
OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(http, call_ctx, hdr)
/**
 * @brief Authenticate the call with HTTP Basic credentials.
 *
 * Credentials set earlier on the context are released and replaced.
 *
 * @param log        the log handle to use
 * @param ctx        the call context to set the credentials on
 * @param username   the username
 * @param password   the password
 * @param url_encode when true, both are URL-encoded before use, as
 *                   RFC 6749 section 2.3.1 prescribes for a client_id
 *                   and client_secret
 * @return true, false when ctx is NULL
 */
bool oauth2_http_call_ctx_basic_auth_set(oauth2_log_t *log,
					 oauth2_http_call_ctx_t *ctx,
					 const char *username,
					 const char *password, bool url_encode);
/** @} */

/**
 * @name Outgoing calls
 * Execute an outgoing HTTP call with libcurl, following up to 5
 * redirects and accepting a response body of up to 1 MB (a larger one
 * fails the call, without a retry). On success
 * the response body is returned in @p response as a newly allocated
 * NUL-terminated string, to be released with oauth2_mem_free(), and
 * the HTTP status code in @p status_code; @p response must not be
 * NULL, @p status_code may be. Any status code received, 4xx and 5xx
 * included, makes a successful call; a call fails, returning false,
 * on a transport error once the configured retries are exhausted, or
 * right away on a timeout, which reports status code 504.
 * oauth2_http_call() is the generic form: it POSTs @p data when
 * non-NULL (with the content type set on the call context) and
 * performs a plain GET otherwise; the _get/_post_form/_post_json
 * variants encode a parameter list or JSON object accordingly. A NULL
 * @p ctx makes the call with libcurl's defaults.
 * @{
 */

/**
 * @brief Perform a GET or POST call.
 *
 * @param log         the log handle to use
 * @param url         the URL to call; must not be NULL
 * @param data        the body to POST, or NULL to GET
 * @param ctx         the call settings, or NULL for the defaults
 * @param response    set to the response body; must not be NULL
 * @param status_code set to the HTTP status code when non-NULL, also
 *                    when the call failed (0 when nothing was
 *                    received)
 * @return true when a response was received, false otherwise
 */
bool oauth2_http_call(oauth2_log_t *log, const char *url, const char *data,
		      oauth2_http_call_ctx_t *ctx, char **response,
		      oauth2_http_status_code_t *status_code);
/** @brief GET a URL with @p params appended to its query string. */
bool oauth2_http_get(oauth2_log_t *log, const char *url,
		     const oauth2_nv_list_t *params,
		     oauth2_http_call_ctx_t *ctx, char **response,
		     oauth2_http_status_code_t *status_code);
/**
 * @brief POST @p params as form-encoded data, setting the content type
 *        on @p ctx accordingly.
 */
bool oauth2_http_post_form(oauth2_log_t *log, const char *url,
			   const oauth2_nv_list_t *params,
			   oauth2_http_call_ctx_t *ctx, char **response,
			   oauth2_http_status_code_t *status_code);
/**
 * @brief POST @p json serialized compactly, setting the content type on
 *        @p ctx to application/json.
 */
bool oauth2_http_post_json(oauth2_log_t *log, const char *url,
			   const json_t *json, oauth2_http_call_ctx_t *ctx,
			   char **response,
			   oauth2_http_status_code_t *status_code);
/** @} */

/**
 * @name Request cookies
 * The Cookie header is parsed on first access - split on ";" and "=",
 * trimmed and URL-decoded - and rewritten from the parsed cookies,
 * URL-encoded again, after a modification.
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
/**
 * @brief Set a cookie in the request's Cookie header, replacing an
 *        existing cookie of that name, e.g. to pass a value on to the
 *        target application.
 * @return true when the header was updated, false on error
 */
bool oauth2_http_request_cookie_set(oauth2_log_t *log, oauth2_http_request_t *r,
				    const char *name, const char *value);
/** @} */

/**
 * @name Outgoing call authentication
 * Set a TLS client certificate/key or basic authentication credentials
 * on an outgoing call context.
 * @{
 */

/**
 * @brief Present a TLS client certificate on the call.
 *
 * @param log      the log handle to use
 * @param ssl_cert the certificate file; must not be NULL
 * @param ssl_key  the private key file; must not be NULL
 * @param ctx      the call context to set them on
 * @return true when set, false when either file is NULL or setting it
 *         failed
 */
bool oauth2_http_auth_client_cert(oauth2_log_t *log, const char *ssl_cert,
				  const char *ssl_key,
				  oauth2_http_call_ctx_t *ctx);
/**
 * @brief Authenticate the call with HTTP Basic credentials used as-is;
 *        see oauth2_http_call_ctx_basic_auth_set() for URL-encoding
 *        them.
 * @return always true
 */
bool oauth2_http_auth_basic(oauth2_log_t *log, const char *username,
			    const char *passwd, oauth2_http_call_ctx_t *ctx);
/** @} */

#endif /* _OAUTH2_HTTP_H_ */
