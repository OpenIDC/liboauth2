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

#include "http_server.h"

#include "oauth2/log.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define OAUTH2_CHECK_SRV_READ_BUF 8192
#define OAUTH2_CHECK_SRV_BACKLOG 1
/* listen-socket accept timeout (seconds) so the thread can observe ->stopping
 */
#define OAUTH2_CHECK_SRV_ACCEPT_TIMEOUT 1
/* per-connection recv timeout (seconds) so a misbehaving test cannot hang us */
#define OAUTH2_CHECK_SRV_RECV_TIMEOUT 5

struct oauth2_check_http_server_t {
	oauth2_log_t *log;
	int listen_fd;
	int port;
	char *url; /* "http://127.0.0.1:<port>" */
	pthread_t thread;
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

static bool srv_write_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);
		if (n <= 0) {
			if ((n < 0) && (errno == EINTR))
				continue;
			return false;
		}
		off += (size_t)n;
	}
	return true;
}

/* read until \r\n\r\n; on success returns header length (incl. terminator),
 * -1 on failure */
static ssize_t srv_read_headers(int fd, char *buf, size_t cap,
				size_t *received_total)
{
	size_t total = 0;
	while (total < cap) {
		ssize_t n = recv(fd, buf + total, cap - total, 0);
		if (n < 0 && errno == EINTR)
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
					return (ssize_t)(i + 1);
				}
			}
		}
	}
	return -1;
}

static void srv_parse_request(oauth2_log_t *log,
			      oauth2_check_http_captured_t *cap, char *headers,
			      size_t headers_len, const char *trailing_body,
			      size_t trailing_body_len, int fd)
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
			ssize_t n =
			    recv(fd, body + got, content_length - got, 0);
			if (n < 0 && errno == EINTR)
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
			      const oauth2_check_http_response_t *r, int fd)
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

static int srv_accept(oauth2_check_http_server_t *s)
{
	while (s->stopping == 0) {
		int conn = accept(s->listen_fd, NULL, NULL);
		if (conn >= 0)
			return conn;
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			/* accept timed out (or was interrupted): re-check
			 * ->stopping and keep waiting for this request */
			continue;
		break;
	}
	return -1;
}

static void *srv_run(void *data)
{
	oauth2_check_http_server_t *s = (oauth2_check_http_server_t *)data;

	/* serve one connection per scripted response, in order; each outbound
	 * call opens a fresh connection (responses say "Connection: close") */
	for (int i = 0; i < s->n_responses; i++) {
		int conn = srv_accept(s);
		if (conn < 0)
			/* accept fails / interrupted by stop(); a well-formed
			 * test drives exactly n_responses requests so this is
			 * only reached at shutdown */
			break;

		/* short timeout so a misbehaving test doesn't hang the suite */
		struct timeval tv = {.tv_sec = OAUTH2_CHECK_SRV_RECV_TIMEOUT,
				     .tv_usec = 0};
		setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		char *buf = oauth2_mem_alloc(OAUTH2_CHECK_SRV_READ_BUF);
		size_t received_total = 0;
		ssize_t hdr_end = srv_read_headers(
		    conn, buf, OAUTH2_CHECK_SRV_READ_BUF, &received_total);
		if (hdr_end < 0) {
			oauth2_mem_free(buf);
			close(conn);
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
		close(conn);
	}

	return NULL;
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

	oauth2_check_http_server_t *s = oauth2_mem_alloc(sizeof(*s));
	memset(s, 0, sizeof(*s));
	s->listen_fd = -1;
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
	if (s->listen_fd < 0)
		goto error;

	int on = 1;
	setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* bounded accept() so srv_run() can observe ->stopping at teardown */
	struct timeval tv = {.tv_sec = OAUTH2_CHECK_SRV_ACCEPT_TIMEOUT,
			     .tv_usec = 0};
	setsockopt(s->listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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

	if (pthread_create(&s->thread, NULL, srv_run, s) != 0)
		goto error;
	s->thread_started = 1;

	return s;

error:
	if (s->listen_fd >= 0)
		close(s->listen_fd);
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
		pthread_join(s->thread, NULL);
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
	if (s->listen_fd >= 0) {
		close(s->listen_fd);
		s->listen_fd = -1;
	}
	srv_free_captured(s);
	srv_free_responses(s);
	oauth2_mem_free(s->url);
	oauth2_log_free(s->log);
	oauth2_mem_free(s);
}

int oauth2_check_http_free_port(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return 0;

	int on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(0);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return 0;
	}

	struct sockaddr_in bound;
	socklen_t bound_len = sizeof(bound);
	int port = 0;
	if (getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0)
		port = ntohs(bound.sin_port);

	close(fd);
	return port;
}
