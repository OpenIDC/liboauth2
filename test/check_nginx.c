/***************************************************************************
 *
 * Copyright (C) 2018-2021 - ZmartZone Holding BV - www.zmartzone.eu
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
	_request->port_start = (u_char *)_url + strlen("https://example.org:");
	_request->port_end =
	    (u_char *)_url + strlen("https://example.org:8080");
	_request->uri = _uri;
	_request->method_name = _method_name;
	_request->args = _args;
	_request->pool = ngx_create_pool(1024, NULL);
	_request->connection = oauth2_mem_alloc(sizeof(ngx_connection_t));
	_request->connection->log = NULL;
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
