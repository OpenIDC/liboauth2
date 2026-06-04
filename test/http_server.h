#ifndef _OAUTH2_CHECK_HTTP_SERVER_H_
#define _OAUTH2_CHECK_HTTP_SERVER_H_

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

/*
 * Plaintext HTTP/1.0 loopback fixture used by the Check-based unit tests to
 * drive the liboauth2 HTTP client (oauth2_http_get/post_form, JWKS/metadata
 * resolution, token verification, OIDC flows, ...) end-to-end without
 * depending on a network service. The server binds to 127.0.0.1 and serves one
 * connection per scripted response, in order, capturing each request; with a
 * single response it accepts one connection and exits. Serving a sequence
 * (oauth2_check_http_server_start_seq) enables multi-request flows such as a
 * discovery-then-jwks-then-token exchange.
 *
 * The server does not route on the request path: it replies with responses[i]
 * to the i-th request, whatever it is, and captures the request for later
 * assertions. Tests that need the server's own URL embedded in a response body
 * (e.g. provider metadata whose jwks_uri points back at the fixture) reserve a
 * port up front with oauth2_check_http_free_port(), format the URL, build the
 * bodies, and start the server on that fixed port with
 * oauth2_check_http_server_start_at().
 *
 * Typical usage in a test:
 *
 *     oauth2_check_http_response_t resp = {.status_code = 200,
 *                                          .content_type = "application/json",
 *                                          .body = "{}"};
 *     oauth2_check_http_server_t *srv = oauth2_check_http_server_start(&resp);
 *     // drive oauth2_http_get(...) against oauth2_check_http_server_url(srv)
 *     const oauth2_check_http_captured_t *cap =
 *         oauth2_check_http_server_wait(srv);
 *     // assert on cap->method, cap->path, cap->headers, cap->body
 *     oauth2_check_http_server_stop(srv);
 *
 * Plaintext only - TLS coverage is out of scope for this fixture.
 */

#include <stddef.h>

#include "oauth2/util.h"

typedef struct oauth2_check_http_response_t {
	int status_code;	  /* e.g. 200, 404 */
	const char *content_type; /* nullable; if set, emitted as Content-Type
				     response header */
	const char *body;	  /* nullable response body (treated as 0-length
				     when NULL) */
	oauth2_nv_list_t *extra_headers; /* nullable; emitted as additional
					    response headers */
} oauth2_check_http_response_t;

typedef struct oauth2_check_http_captured_t {
	char *method;		   /* "GET", "POST", ... */
	char *path;		   /* request-target, e.g. "/p?a=1" */
	oauth2_nv_list_t *headers; /* request headers, name preserved */
	char *body;		   /* request body bytes (may be NULL) */
	size_t body_len;	   /* length of body in bytes */
} oauth2_check_http_captured_t;

typedef struct oauth2_check_http_server_t oauth2_check_http_server_t;

/*
 * Start a loopback HTTP server that will handle exactly one connection with the
 * given response on a kernel-assigned free port. Returns NULL on bind/listen
 * failure. The responses are deep-copied, so the caller may free its inputs
 * immediately after this call returns.
 */
oauth2_check_http_server_t *
oauth2_check_http_server_start(const oauth2_check_http_response_t *response);

/*
 * Start a loopback HTTP server that serves `n_responses` connections on a
 * kernel-assigned free port, replying with responses[i] to the i-th request and
 * capturing each one. Use this to test flows that issue more than one outbound
 * request. The test must drive exactly `n_responses` requests; a test that
 * issues fewer will only release the server thread on stop(). Returns NULL on
 * bad arguments or bind/listen failure.
 */
oauth2_check_http_server_t *oauth2_check_http_server_start_seq(
    const oauth2_check_http_response_t *responses, int n_responses);

/*
 * As oauth2_check_http_server_start_seq(), but binds the listening socket to a
 * specific `port` (0 = kernel-assigned). Use together with
 * oauth2_check_http_free_port() when a scripted response body must embed the
 * server's own URL.
 */
oauth2_check_http_server_t *oauth2_check_http_server_start_at(
    int port, const oauth2_check_http_response_t *responses, int n_responses);

/* The port the server bound to. */
int oauth2_check_http_server_port(const oauth2_check_http_server_t *s);

/* "http://127.0.0.1:<port>", owned by the server (valid until stop). */
const char *oauth2_check_http_server_url(const oauth2_check_http_server_t *s);

/*
 * Wait for the server thread to finish handling the request(s) and return the
 * first captured request. Returns NULL on accept/read failure. Safe to call
 * multiple times; subsequent calls return the same pointer.
 */
const oauth2_check_http_captured_t *
oauth2_check_http_server_wait(oauth2_check_http_server_t *s);

/*
 * Join the server thread (if needed) and return the request captured for the
 * `index`-th scripted response, or NULL if that request was never made. wait()
 * is equivalent to captured(s, 0).
 */
const oauth2_check_http_captured_t *
oauth2_check_http_server_captured(oauth2_check_http_server_t *s, int index);

/* Join the server thread (if needed) and return the number of requests handled.
 */
int oauth2_check_http_server_request_count(oauth2_check_http_server_t *s);

/* Join the server thread and release all resources. */
void oauth2_check_http_server_stop(oauth2_check_http_server_t *s);

/*
 * Bind+release a loopback TCP port and return the (now likely-free) port
 * number. Use this to obtain a port to format into a URL before starting the
 * server on that same port. Returns 0 on failure.
 */
int oauth2_check_http_free_port(void);

#endif /* _OAUTH2_CHECK_HTTP_SERVER_H_ */
