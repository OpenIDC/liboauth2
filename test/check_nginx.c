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

#include "check_liboauth2.h"

#include "oauth2/mem.h"
#include "oauth2/nginx.h"

#include <check.h>

static oauth2_log_t *_log = 0;
static ngx_http_request_t *_request = NULL;
static char *_url = "https://example.org:8080/some?jan=piet";
static ngx_str_t _uri = ngx_string("/some");
static ngx_str_t _method_name = ngx_string("POST");
static ngx_str_t _args = ngx_string("param=value");

static void setup(void)
{
	ngx_table_elt_t *h = NULL;

	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
	_request = oauth2_mem_alloc(sizeof(ngx_http_request_t));
	_request->schema_start = (u_char *)_url;
	_request->schema_end = (u_char *)_url + strlen("https");
	_request->host_start = (u_char *)_url + strlen("https://");
	_request->host_end = (u_char *)_url + strlen("https://example.org");
	_request->uri = _uri;
	_request->method_name = _method_name;
	_request->args = _args;
	_request->pool = ngx_create_pool(1024, NULL);
	_request->connection = oauth2_mem_alloc(sizeof(ngx_connection_t));
	_request->connection->log = NULL;
	_request->connection->local_sockaddr =
	    oauth2_mem_alloc(sizeof(struct sockaddr_in));
	_request->connection->local_sockaddr->sa_family = AF_INET;
	((struct sockaddr_in *)_request->connection->local_sockaddr)->sin_port =
	    htons(8080);
	_request->http_connection =
	    oauth2_mem_alloc(sizeof(ngx_http_connection_t));
	_request->http_connection->ssl = 1;
	ngx_list_init(&_request->headers_out.headers, _request->pool, 20,
		      sizeof(ngx_table_elt_t));
	ngx_list_init(&_request->headers_in.headers, _request->pool, 20,
		      sizeof(ngx_table_elt_t));
	h = ngx_list_push(&_request->headers_in.headers);
	h->hash = ngx_hash(ngx_hash(ngx_hash('H', 'o'), 's'), 't');
	h->key.data = (u_char *)oauth2_strdup("Host");
	h->key.len = sizeof("Host") - 1;
	h->lowcase_key = (u_char *)"host";
	h->value.data = (u_char *)oauth2_strdup("example.org");
	h->value.len = sizeof("example.org") - 1;
}

static void list_free(ngx_list_t *list)
{
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_uint_t i;
	part = &list->part;
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
		oauth2_mem_free(h[i].value.data);
		oauth2_mem_free(h[i].key.data);
	}
	oauth2_mem_free(list->part.elts);
}

static void teardown(void)
{

	list_free(&_request->headers_out.headers);
	list_free(&_request->headers_in.headers);
	oauth2_mem_free(_request->http_connection);
	oauth2_mem_free(_request->connection->local_sockaddr);
	oauth2_mem_free(_request->connection);
	ngx_destroy_pool(_request->pool);
	oauth2_mem_free(_request);
	oauth2_shutdown(_log);
}

START_TEST(test_request_context)
{
	oauth2_nginx_request_context_t *ctx = NULL;

	ctx = oauth2_nginx_request_context_init(_request);
	ck_assert_ptr_ne(ctx, NULL);
	// TODO: check request values

	oauth2_nginx_request_context_free(ctx);
}
END_TEST

START_TEST(test_nginx_http_response_set)
{
	ngx_int_t nrc = NGX_ERROR;
	oauth2_http_response_t *response = NULL;

	response = oauth2_http_response_init(_log);
	oauth2_http_response_header_set(_log, response, "Content-Length",
					"512");
	nrc = oauth2_nginx_http_response_set(_log, response, _request);
	ck_assert_int_eq(nrc, NGX_OK);
	// TODO: check status code and response headers

	oauth2_http_response_free(_log, response);
}
END_TEST

/*
 */
Suite *oauth2_check_nginx_suite()
{
	Suite *s = suite_create("nginx");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_request_context);
	tcase_add_test(c, test_nginx_http_response_set);

	suite_add_tcase(s, c);

	return s;
}
