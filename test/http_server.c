/***************************************************************************
 *
 * Copyright (C) 2018-2026 - ZmartZone Holding BV
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

#include "http_server.h"

#include "oauth2/log.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The sockets and the server thread are the only platform-specific parts of
 * this fixture: BSD sockets and pthreads everywhere, Winsock and a CRT thread
 * on Windows, where a socket is not an int and errors do not come via errno.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <process.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET srv_sock_t;
typedef int srv_ssize_t;
#define SRV_INVALID_SOCKET INVALID_SOCKET
#define srv_sock_valid(s) ((s) != INVALID_SOCKET)
#define srv_close_socket(s) closesocket(s)
#define srv_last_error() WSAGetLastError()
#define srv_error_is_retry(e)                                                  \
	(((e) == WSAEINTR) || ((e) == WSAEWOULDBLOCK) || ((e) == WSAETIMEDOUT))
#define strcasecmp _stricmp
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int srv_sock_t;
typedef ssize_t srv_ssize_t;
#define SRV_INVALID_SOCKET (-1)
#define srv_sock_valid(s) ((s) >= 0)
#define srv_close_socket(s) close(s)
#define srv_last_error() errno
#define srv_error_is_retry(e)                                                  \
	(((e) == EINTR) || ((e) == EAGAIN) || ((e) == EWOULDBLOCK))
#endif

#define OAUTH2_CHECK_SRV_READ_BUF 8192
#define OAUTH2_CHECK_SRV_BACKLOG 1
/* listen-socket accept timeout (seconds) so the thread can observe ->stopping
 */
#define OAUTH2_CHECK_SRV_ACCEPT_TIMEOUT 1
/* per-connection recv timeout (seconds) so a misbehaving test cannot hang us */
#define OAUTH2_CHECK_SRV_RECV_TIMEOUT 5

struct oauth2_check_http_server_t {
	oauth2_log_t *log;
	srv_sock_t listen_fd;
	int port;
	char *url; /* "http://127.0.0.1:<port>" */
#ifdef _WIN32
	HANDLE thread;
#else
	pthread_t thread;
#endif
	int thread_started;
	int joined;
	volatile sig_atomic_t stopping;
	oauth2_check_http_response_t
	    *responses; /* deep-copied, served in order */
	int n_responses;
	oauth2_check_http_captured_t
	    *captured;	    /* one slot per scripted response */
	int captured_count; /* number of requests actually handled */
};

#ifdef _WIN32
/* Winsock wants a one-time initialization per process */
static void srv_net_init(void)
{
	static int initialized = 0;
	WSADATA wsa;
	if (initialized == 0) {
		WSAStartup(MAKEWORD(2, 2), &wsa);
		initialized = 1;
	}
}
#else
#define srv_net_init()
#endif

/* SO_RCVTIMEO takes a struct timeval on POSIX and milliseconds on Windows */
static void srv_set_recv_timeout(srv_sock_t fd, int seconds)
{
#ifdef _WIN32
	DWORD tv = (DWORD)seconds * 1000;
#else
	struct timeval tv = {.tv_sec = seconds, .tv_usec = 0};
#endif
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
}

static bool srv_write_all(srv_sock_t fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		srv_ssize_t n = send(fd, buf + off, (int)(len - off), 0);
		if (n <= 0) {
			if ((n < 0) && (srv_last_error() == EINTR))
				continue;
			return false;
		}
		off += (size_t)n;
	}
	return true;
}

/* read until \r\n\r\n; on success returns header length (incl. terminator),
 * -1 on failure */
static srv_ssize_t srv_read_headers(srv_sock_t fd, char *buf, size_t cap,
				    size_t *received_total)
{
	size_t total = 0;
	while (total < cap) {
		srv_ssize_t n = recv(fd, buf + total, (int)(cap - total), 0);
		if (n < 0 && srv_last_error() == EINTR)
			continue;
		if (n <= 0)
			return -1;
		total += (size_t)n;
		/* look for end of header block */
		if (total >= 4) {
			for (size_t i = 3; i < total; i++) {
				if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
				    buf[i - 1] == '\r' && buf[i] == '\n') {
					*received_total = total;
					return (srv_ssize_t)(i + 1);
				}
			}
		}
	}
	return -1;
}

static void srv_parse_request(oauth2_log_t *log,
			      oauth2_check_http_captured_t *cap, char *headers,
			      size_t headers_len, const char *trailing_body,
			      size_t trailing_body_len, srv_sock_t fd)
{
	cap->headers = oauth2_nv_list_init(log);

	/* request line: METHOD<sp>PATH<sp>HTTP/1.x\r\n */
	char *eol = strstr(headers, "\r\n");
	if (eol == NULL)
		return;
	*eol = '\0';
	char *sp1 = strchr(headers, ' ');
	if (sp1 == NULL)
		return;
	*sp1 = '\0';
	char *sp2 = strchr(sp1 + 1, ' ');
	if (sp2 == NULL)
		return;
	*sp2 = '\0';
	cap->method = oauth2_strdup(headers);
	cap->path = oauth2_strdup(sp1 + 1);

	/* header lines until empty line */
	char *line = eol + 2;
	size_t content_length = 0;
	while (line < headers + headers_len) {
		char *next = strstr(line, "\r\n");
		if (next == line)
			break;
		if (next == NULL)
			break;
		*next = '\0';
		char *colon = strchr(line, ':');
		if (colon != NULL) {
			*colon = '\0';
			char *name = line;
			char *value = colon + 1;
			while (*value == ' ' || *value == '\t')
				value++;
			oauth2_nv_list_add(log, cap->headers, name, value);
			if (strcasecmp(name, "Content-Length") == 0)
				content_length =
				    (size_t)strtoul(value, NULL, 10);
		}
		line = next + 2;
	}

	/* body: anything past headers we already read, plus more reads if
	 * needed
	 */
	if (content_length > 0) {
		char *body = oauth2_mem_alloc(content_length + 1);
		size_t got = 0;
		if (trailing_body_len > 0) {
			size_t take = trailing_body_len < content_length
					  ? trailing_body_len
					  : content_length;
			memcpy(body, trailing_body, take);
			got = take;
		}
		while (got < content_length) {
			srv_ssize_t n = recv(fd, body + got,
					     (int)(content_length - got), 0);
			if (n < 0 && srv_last_error() == EINTR)
				continue;
			if (n <= 0)
				break;
			got += (size_t)n;
		}
		body[got] = '\0';
		cap->body = body;
		cap->body_len = got;
	}
}

static const char *srv_reason(int code)
{
	switch (code) {
	case 200:
		return "OK";
	case 201:
		return "Created";
	case 204:
		return "No Content";
	case 400:
		return "Bad Request";
	case 401:
		return "Unauthorized";
	case 403:
		return "Forbidden";
	case 404:
		return "Not Found";
	case 500:
		return "Internal Server Error";
	case 502:
		return "Bad Gateway";
	case 503:
		return "Service Unavailable";
	default:
		return "Unknown";
	}
}

/* oauth2_nv_list_loop callback: appends "Name: value\r\n" to *(char **)rec */
static bool srv_append_hdr(oauth2_log_t *log, void *rec, const char *key,
			   const char *value)
{
	char **acc = (char **)rec;
	*acc = oauth2_stradd(*acc, key, ": ", value);
	*acc = oauth2_stradd(*acc, "\r\n", NULL, NULL);
	return true;
}

static void srv_send_response(oauth2_check_http_server_t *s,
			      const oauth2_check_http_response_t *r,
			      srv_sock_t fd)
{
	size_t body_len = r->body ? strlen(r->body) : 0;
	char numbuf[32];
	char *head = NULL;

	snprintf(numbuf, sizeof(numbuf), "HTTP/1.0 %d ", r->status_code);
	head = oauth2_stradd(NULL, numbuf, srv_reason(r->status_code), "\r\n");

	if (r->content_type != NULL)
		head = oauth2_stradd(head, "Content-Type: ", r->content_type,
				     "\r\n");

	if (r->extra_headers != NULL) {
		char *hdrs = NULL;
		oauth2_nv_list_loop(s->log, r->extra_headers, srv_append_hdr,
				    &hdrs);
		if (hdrs != NULL) {
			head = oauth2_stradd(head, hdrs, NULL, NULL);
			oauth2_mem_free(hdrs);
		}
	}

	snprintf(numbuf, sizeof(numbuf), "%zu", body_len);
	head = oauth2_stradd(head, "Content-Length: ", numbuf, "\r\n");
	head = oauth2_stradd(head, "Connection: close\r\n\r\n", NULL, NULL);

	srv_write_all(fd, head, strlen(head));
	if (body_len > 0)
		srv_write_all(fd, r->body, body_len);

	oauth2_mem_free(head);
}

static srv_sock_t srv_accept(oauth2_check_http_server_t *s)
{
	while (s->stopping == 0) {
		srv_sock_t conn = accept(s->listen_fd, NULL, NULL);
		if (srv_sock_valid(conn))
			return conn;
		if (srv_error_is_retry(srv_last_error()))
			/* accept timed out (or was interrupted): re-check
			 * ->stopping and keep waiting for this request */
			continue;
		break;
	}
	return SRV_INVALID_SOCKET;
}

static void *srv_run(void *data)
{
	oauth2_check_http_server_t *s = (oauth2_check_http_server_t *)data;

	/* serve one connection per scripted response, in order; each outbound
	 * call opens a fresh connection (responses say "Connection: close") */
	for (int i = 0; i < s->n_responses; i++) {
		srv_sock_t conn = srv_accept(s);
		if (!srv_sock_valid(conn))
			/* accept fails / interrupted by stop(); a well-formed
			 * test drives exactly n_responses requests so this is
			 * only reached at shutdown */
			break;

		/* short timeout so a misbehaving test doesn't hang the suite */
		srv_set_recv_timeout(conn, OAUTH2_CHECK_SRV_RECV_TIMEOUT);

		char *buf = oauth2_mem_alloc(OAUTH2_CHECK_SRV_READ_BUF);
		size_t received_total = 0;
		srv_ssize_t hdr_end = srv_read_headers(
		    conn, buf, OAUTH2_CHECK_SRV_READ_BUF, &received_total);
		if (hdr_end < 0) {
			oauth2_mem_free(buf);
			srv_close_socket(conn);
			break;
		}
		/* NUL-terminate inside the header block (replacing the final
		 * '\n' of the "\r\n\r\n" terminator). This bounds the
		 * header-parser's strstr calls without touching the first byte
		 * of any inline body bytes at buf[hdr_end]. */
		buf[hdr_end - 1] = '\0';
		size_t trailing_len = received_total - (size_t)hdr_end;
		const char *trailing =
		    (trailing_len > 0) ? (buf + hdr_end) : NULL;

		oauth2_check_http_captured_t *cap = &s->captured[i];
		srv_parse_request(s->log, cap, buf, (size_t)hdr_end, trailing,
				  trailing_len, conn);
		if ((cap->method != NULL) && (cap->path != NULL))
			s->captured_count = i + 1;

		/* gated request trace, handy when scripting multi-request flows
		 * (export OAUTH2_CHECK_HTTP_TRACE=1) */
		if (getenv("OAUTH2_CHECK_HTTP_TRACE") != NULL) {
			fprintf(
			    stderr,
			    "[check-http-server] #%d %s %s (body_len=%zu)\n", i,
			    cap->method ? cap->method : "?",
			    cap->path ? cap->path : "?", cap->body_len);
			fflush(stderr);
		}

		srv_send_response(s, &s->responses[i], conn);

		oauth2_mem_free(buf);
		srv_close_socket(conn);
	}

	return NULL;
}

#ifdef _WIN32
static unsigned __stdcall srv_run_thread(void *data)
{
	srv_run(data);
	return 0;
}
#endif

static bool srv_thread_start(oauth2_check_http_server_t *s)
{
#ifdef _WIN32
	s->thread = (HANDLE)_beginthreadex(NULL, 0, srv_run_thread, s, 0, NULL);
	return (s->thread != NULL);
#else
	return (pthread_create(&s->thread, NULL, srv_run, s) == 0);
#endif
}

static void srv_thread_join(oauth2_check_http_server_t *s)
{
#ifdef _WIN32
	WaitForSingleObject(s->thread, INFINITE);
	CloseHandle(s->thread);
#else
	pthread_join(s->thread, NULL);
#endif
}

static void srv_free_captured(oauth2_check_http_server_t *s)
{
	if (s->captured == NULL)
		return;
	for (int i = 0; i < s->n_responses; i++) {
		oauth2_mem_free(s->captured[i].method);
		oauth2_mem_free(s->captured[i].path);
		oauth2_mem_free(s->captured[i].body);
		oauth2_nv_list_free(s->log, s->captured[i].headers);
	}
	oauth2_mem_free(s->captured);
	s->captured = NULL;
}

static void srv_free_responses(oauth2_check_http_server_t *s)
{
	if (s->responses == NULL)
		return;
	for (int i = 0; i < s->n_responses; i++) {
		oauth2_mem_free((char *)s->responses[i].content_type);
		oauth2_mem_free((char *)s->responses[i].body);
		oauth2_nv_list_free(s->log, s->responses[i].extra_headers);
	}
	oauth2_mem_free(s->responses);
	s->responses = NULL;
}

oauth2_check_http_server_t *oauth2_check_http_server_start_at(
    int port, const oauth2_check_http_response_t *responses, int n_responses)
{
	if ((responses == NULL) || (n_responses < 1))
		return NULL;

	srv_net_init();

	oauth2_check_http_server_t *s = oauth2_mem_alloc(sizeof(*s));
	memset(s, 0, sizeof(*s));
	s->listen_fd = SRV_INVALID_SOCKET;
	s->log = oauth2_log_init(OAUTH2_LOG_WARN, NULL);
	s->n_responses = n_responses;

	/* deep-copy the scripted responses so the caller may free its inputs */
	s->responses = oauth2_mem_alloc(sizeof(oauth2_check_http_response_t) *
					n_responses);
	memset(s->responses, 0,
	       sizeof(oauth2_check_http_response_t) * n_responses);
	for (int i = 0; i < n_responses; i++) {
		s->responses[i].status_code = responses[i].status_code;
		if (responses[i].content_type != NULL)
			s->responses[i].content_type =
			    oauth2_strdup(responses[i].content_type);
		if (responses[i].body != NULL)
			s->responses[i].body = oauth2_strdup(responses[i].body);
		if (responses[i].extra_headers != NULL)
			s->responses[i].extra_headers = oauth2_nv_list_clone(
			    s->log, responses[i].extra_headers);
	}

	s->captured = oauth2_mem_alloc(sizeof(oauth2_check_http_captured_t) *
				       n_responses);
	memset(s->captured, 0,
	       sizeof(oauth2_check_http_captured_t) * n_responses);

	s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!srv_sock_valid(s->listen_fd))
		goto error;

	int on = 1;
	setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
		   sizeof(on));

	/* bounded accept() so srv_run() can observe ->stopping at teardown */
	srv_set_recv_timeout(s->listen_fd, OAUTH2_CHECK_SRV_ACCEPT_TIMEOUT);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons((uint16_t)port);
	if (bind(s->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto error;
	if (listen(s->listen_fd, OAUTH2_CHECK_SRV_BACKLOG) < 0)
		goto error;

	/* recover the actual bound port */
	struct sockaddr_in bound;
	socklen_t bound_len = sizeof(bound);
	if (getsockname(s->listen_fd, (struct sockaddr *)&bound, &bound_len) <
	    0)
		goto error;
	s->port = ntohs(bound.sin_port);

	char numbuf[16];
	snprintf(numbuf, sizeof(numbuf), "%d", s->port);
	s->url = oauth2_stradd(NULL, "http://127.0.0.1:", numbuf, NULL);

	if (srv_thread_start(s) == false)
		goto error;
	s->thread_started = 1;

	return s;

error:
	if (srv_sock_valid(s->listen_fd))
		srv_close_socket(s->listen_fd);
	srv_free_responses(s);
	srv_free_captured(s);
	oauth2_mem_free(s->url);
	oauth2_log_free(s->log);
	oauth2_mem_free(s);
	return NULL;
}

oauth2_check_http_server_t *oauth2_check_http_server_start_seq(
    const oauth2_check_http_response_t *responses, int n_responses)
{
	return oauth2_check_http_server_start_at(0, responses, n_responses);
}

oauth2_check_http_server_t *
oauth2_check_http_server_start(const oauth2_check_http_response_t *response)
{
	return oauth2_check_http_server_start_seq(response, 1);
}

int oauth2_check_http_server_port(const oauth2_check_http_server_t *s)
{
	return s ? s->port : 0;
}

const char *oauth2_check_http_server_url(const oauth2_check_http_server_t *s)
{
	return s ? s->url : NULL;
}

static void srv_join(oauth2_check_http_server_t *s)
{
	if (s->thread_started && !s->joined) {
		srv_thread_join(s);
		s->joined = 1;
	}
}

int oauth2_check_http_server_request_count(oauth2_check_http_server_t *s)
{
	if (s == NULL)
		return 0;
	srv_join(s);
	return s->captured_count;
}

const oauth2_check_http_captured_t *
oauth2_check_http_server_captured(oauth2_check_http_server_t *s, int index)
{
	if (s == NULL)
		return NULL;
	int count = oauth2_check_http_server_request_count(s);
	if ((index < 0) || (index >= count))
		return NULL;
	return &s->captured[index];
}

const oauth2_check_http_captured_t *
oauth2_check_http_server_wait(oauth2_check_http_server_t *s)
{
	return oauth2_check_http_server_captured(s, 0);
}

void oauth2_check_http_server_stop(oauth2_check_http_server_t *s)
{
	if (s == NULL)
		return;
	/* signal the accept loop to exit even if the test drove fewer requests
	 * than were scripted, then join */
	s->stopping = 1;
	srv_join(s);
	if (srv_sock_valid(s->listen_fd)) {
		srv_close_socket(s->listen_fd);
		s->listen_fd = SRV_INVALID_SOCKET;
	}
	srv_free_captured(s);
	srv_free_responses(s);
	oauth2_mem_free(s->url);
	oauth2_log_free(s->log);
	oauth2_mem_free(s);
}

int oauth2_check_http_free_port(void)
{
	srv_net_init();

	srv_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!srv_sock_valid(fd))
		return 0;

	int on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(0);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		srv_close_socket(fd);
		return 0;
	}

	struct sockaddr_in bound;
	socklen_t bound_len = sizeof(bound);
	int port = 0;
	if (getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0)
		port = ntohs(bound.sin_port);

	srv_close_socket(fd);
	return port;
}
