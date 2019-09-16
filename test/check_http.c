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

#include "check_liboauth2.h"
#include "oauth2/http.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"
#include <check.h>

static oauth2_log_t *log = NULL;

static void setup(void)
{
	log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
	// for coverage
	oauth2_http_request_free(log, NULL);
}

static void teardown(void)
{
	oauth2_shutdown(log);
}

static void *faulty_alloc(size_t amt)
{
	return NULL;
}

START_TEST(test_request_scheme)
{
	char *scheme = NULL;
	oauth2_http_request_t *r = NULL;
	bool rc;

	// set null scheme
	scheme = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_scheme_set(log, r, NULL);
	ck_assert_int_eq(rc, false);
	oauth2_http_request_free(log, r);

	// set no scheme and get default
	scheme = NULL;
	r = oauth2_http_request_init(log);
	scheme = oauth2_http_request_scheme_get(log, r);
	ck_assert_str_eq(scheme, "https");
	oauth2_mem_free(scheme);
	oauth2_http_request_free(log, r);

	// set scheme via native setting
	scheme = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_scheme_set(log, r, "http");
	scheme = oauth2_http_request_scheme_get(log, r);
	ck_assert_str_eq(scheme, "http");
	oauth2_mem_free(scheme);
	oauth2_http_request_free(log, r);

	// set scheme via X-Forwarded-Proto
	scheme = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_scheme_set(log, r, "http");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto", "https");
	scheme = oauth2_http_request_scheme_get(log, r);
	ck_assert_str_eq(scheme, "https");
	oauth2_mem_free(scheme);
	oauth2_http_request_free(log, r);

	// lowercase header
	scheme = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_scheme_set(log, r, "http");
	oauth2_http_request_header_set(log, r, "x-forwarded-proto", "https");
	scheme = oauth2_http_request_scheme_get(log, r);
	ck_assert_str_eq(scheme, "https");
	oauth2_mem_free(scheme);
	oauth2_http_request_free(log, r);

	// set scheme via X-Forwarded-Proto with multiple entries
	scheme = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_scheme_set(log, r, "http");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto",
				       "https, http");
	scheme = oauth2_http_request_scheme_get(log, r);
	ck_assert_str_eq(scheme, "https");
	oauth2_mem_free(scheme);
	oauth2_http_request_free(log, r);

	// set no scheme and add some headers
	r = oauth2_http_request_init(log);
	oauth2_http_request_header_set(log, r, "One", "1");
	oauth2_http_request_header_set(log, r, "Two", "2");
	scheme = oauth2_http_request_scheme_get(log, r);
	ck_assert_str_eq(scheme, "https");
	oauth2_mem_free(scheme);
	oauth2_http_request_free(log, r);

	// get scheme from null request
	scheme = NULL;
	scheme = oauth2_http_request_scheme_get(log, NULL);
	ck_assert_ptr_eq(scheme, NULL);
}
END_TEST

START_TEST(test_request_hostname)
{
	char *hostname = NULL;
	oauth2_http_request_t *r = NULL;
	bool rc;

	// get default hostname null
	hostname = NULL;
	hostname = oauth2_http_request_hostname_get(log, NULL);
	ck_assert_ptr_eq(hostname, NULL);

	// set null hostname
	hostname = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_hostname_set(log, r, NULL);
	ck_assert_int_eq(rc, false);
	oauth2_http_request_free(log, r);

	// set and get hostname
	hostname = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	hostname = oauth2_http_request_hostname_get(log, r);
	ck_assert_str_eq(hostname, "internal");
	oauth2_mem_free(hostname);
	oauth2_http_request_free(log, r);

	// set native hostname but override via X-Forwarded-Host
	hostname = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Host", "external");
	hostname = oauth2_http_request_hostname_get(log, r);
	ck_assert_str_eq(hostname, "external");
	oauth2_mem_free(hostname);
	oauth2_http_request_free(log, r);

	// set native hostname but override via X-Forwarded-Host that includes
	// port
	hostname = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Host",
				       "external:8080");
	hostname = oauth2_http_request_hostname_get(log, r);
	ck_assert_str_eq(hostname, "external");
	oauth2_mem_free(hostname);
	oauth2_http_request_free(log, r);
}
END_TEST

START_TEST(test_request_port)
{
	char *port = NULL;
	oauth2_http_request_t *r = NULL;
	bool rc;

	// get default port null
	port = NULL;
	r = oauth2_http_request_init(log);
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// set native port
	port = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_port_set(log, r, 443);
	ck_assert_int_eq(rc, true);
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get port via X-Forwareded-Port
	port = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_header_set(log, r, "X-Forwarded-Port", "8080");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_str_eq(port, "8080");
	oauth2_mem_free(port);
	oauth2_http_request_free(log, r);

	// get port via X-Forwarded-Host overriding Host
	port = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_header_set(log, r, "Host", "internal:8282");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Host",
				       "external:8181");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_str_eq(port, "8181");
	oauth2_mem_free(port);
	oauth2_http_request_free(log, r);

	// get port via Host that includes port
	port = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_header_set(log, r, "Host", "internal:8282");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_str_eq(port, "8282");
	oauth2_mem_free(port);
	oauth2_http_request_free(log, r);

	// get port as null default for scheme, skipping Host header that
	// doesn't contain a port
	port = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_scheme_set(log, r, "http");
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get default port null, skipping Host and X-Forwarded-Host that don't
	// contain a port
	port = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_header_set(log, r, "Host", "internal");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Host", "external");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get default port null for https scheme, skipping Host that doesn't
	// contain a port
	port = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_scheme_set(log, r, "https");
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get native port set to default scheme port
	port = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_port_set(log, r, 443);
	ck_assert_int_eq(rc, true);
	oauth2_http_request_scheme_set(log, r, "https");
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get native port, skipping Host that doesn't contain a port
	port = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_port_set(log, r, 8080);
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_str_eq(port, "8080");
	oauth2_mem_free(port);
	oauth2_http_request_free(log, r);

	// get default port for scheme determined via X-Forwarded-Proto,
	// overriding native port
	port = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_port_set(log, r, 8080);
	oauth2_http_request_header_set(log, r, "Host", "internal");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto", "https");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get default port null for default scheme https
	port = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_port_set(log, r, 443);
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get default port null for scheme http
	port = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_scheme_set(log, r, "http");
	rc = oauth2_http_request_port_set(log, r, 80);
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_ptr_eq(port, NULL);
	oauth2_http_request_free(log, r);

	// get native port 80 overriding provided scheme
	port = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_port_set(log, r, 80);
	oauth2_http_request_scheme_set(log, r, "https");
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_str_eq(port, "80");
	oauth2_mem_free(port);
	oauth2_http_request_free(log, r);

	// get native port 8080 overriding provided scheme
	port = NULL;
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_port_set(log, r, 8080);
	oauth2_http_request_scheme_set(log, r, "https");
	oauth2_http_request_header_set(log, r, "Host", "internal");
	port = oauth2_http_request_port_get(log, r);
	ck_assert_str_eq(port, "8080");
	oauth2_mem_free(port);
	oauth2_http_request_free(log, r);
}
END_TEST

START_TEST(test_request_header)
{
	const char *value = NULL;
	oauth2_http_request_t *r = NULL;
	oauth2_mem_alloc_fn_t alloc_save;
	bool rc;

	// set a bunch of headers and retrieve one of them
	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_header_set(log, r, "One", "1");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Two", "2");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Three", "3");
	ck_assert_int_eq(rc, true);
	value = oauth2_http_request_header_get(log, r, "Two");
	ck_assert_str_eq(value, "2");
	oauth2_http_request_free(log, r);

	// retrieve null header from request
	r = oauth2_http_request_init(log);
	value = oauth2_http_request_header_get(log, r, NULL);
	ck_assert_ptr_eq(value, NULL);
	oauth2_http_request_free(log, r);

	// retrieve from null request
	r = NULL;
	value = oauth2_http_request_header_get(log, r, "Two");
	ck_assert_ptr_eq(value, NULL);

	// retrieve null header from null request
	r = NULL;
	value = oauth2_http_request_header_get(log, r, NULL);
	ck_assert_ptr_eq(value, NULL);

	// set header using failing memory allocation
	r = NULL;
	r = oauth2_http_request_init(log);

	alloc_save = oauth2_mem_get_alloc();
	oauth2_mem_set_alloc_funcs(faulty_alloc, oauth2_mem_get_realloc(),
				   oauth2_mem_get_dealloc());

	rc = oauth2_http_request_header_set(log, r, "One", "1");
	ck_assert_int_eq(rc, false);
	oauth2_http_request_free(log, r);

	// create request using failing memory allocation
	r = oauth2_http_request_init(log);
	ck_assert_ptr_eq(r, NULL);

	// reset the memory allocator function to their defaults
	oauth2_mem_set_alloc_funcs(alloc_save, oauth2_mem_get_realloc(),
				   oauth2_mem_get_dealloc());
}
END_TEST

START_TEST(test_url_base)
{
	char *base = NULL;
	oauth2_http_request_t *r = NULL;

	// non-initialized
	base = NULL;
	r = oauth2_http_request_init(log);
	base = oauth2_http_request_url_base_get(log, r);
	ck_assert_ptr_eq(base, NULL);
	oauth2_http_request_free(log, r);

	// only hostname initialized, defaults to https
	base = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	base = oauth2_http_request_url_base_get(log, r);
	ck_assert_str_eq(base, "https://internal");
	oauth2_mem_free(base);
	oauth2_http_request_free(log, r);

	// hostname and port initialized, scheme defaults to https
	base = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	oauth2_http_request_port_set(log, r, 8080);
	base = oauth2_http_request_url_base_get(log, r);
	ck_assert_str_eq(base, "https://internal:8080");
	oauth2_mem_free(base);
	oauth2_http_request_free(log, r);

	// X-Forwarded-Host with port provided
	base = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	oauth2_http_request_port_set(log, r, 8080);
	oauth2_http_request_header_set(log, r, "X-Forwarded-Host",
				       "external:9000");
	base = oauth2_http_request_url_base_get(log, r);
	ck_assert_str_eq(base, "https://external:9000");
	oauth2_mem_free(base);
	oauth2_http_request_free(log, r);

	// X-Forwarded-Proto and X-Forwarded-Host provided
	base = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	oauth2_http_request_port_set(log, r, 8080);
	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto", "http");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Host",
				       "external:9000");
	base = oauth2_http_request_url_base_get(log, r);
	ck_assert_str_eq(base, "http://external:9000");
	oauth2_mem_free(base);
	oauth2_http_request_free(log, r);

	// X-Forwarded-Proto, X-Forwarded-Host and X-Forwarded-Port provided
	base = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_hostname_set(log, r, "internal");
	oauth2_http_request_port_set(log, r, 8080);
	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto", "http");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Host",
				       "external:9000");
	oauth2_http_request_header_set(log, r, "X-Forwarded-Port", "8000");
	base = oauth2_http_request_url_base_get(log, r);
	ck_assert_str_eq(base, "http://external:8000");
	oauth2_mem_free(base);
	oauth2_http_request_free(log, r);
}
END_TEST

START_TEST(test_url_get)
{
	char *url = NULL;
	oauth2_http_request_t *r = NULL;

	// mostly test backwards compatibility

	url = NULL;
	r = oauth2_http_request_init(log);
	oauth2_http_request_header_set(log, r, "Host", "www.example.com");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "https://www.example.com");
	oauth2_mem_free(url);

	oauth2_http_request_header_set(log, r, "X-Forwarded-Host",
				       "www.outer.com");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "https://www.outer.com");
	oauth2_mem_free(url);

	oauth2_http_request_header_set(log, r, "X-Forwarded-Host",
				       "www.outer.com:654");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "https://www.outer.com:654");
	oauth2_mem_free(url);

	oauth2_http_request_header_set(log, r, "X-Forwarded-Port", "321");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "https://www.outer.com:321");
	oauth2_mem_free(url);

	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto", "http");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "http://www.outer.com:321");
	oauth2_mem_free(url);

	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto",
				       "https, http");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "https://www.outer.com:321");
	oauth2_mem_free(url);

	// add a space after the comma...
	oauth2_http_request_header_set(log, r, "X-Forwarded-Proto",
				       "https , http");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "https://www.outer.com:321");
	oauth2_mem_free(url);

	oauth2_http_request_header_unset(log, r, "X-Forwarded-Host");
	oauth2_http_request_header_unset(log, r, "X-Forwarded-Port");
	url = oauth2_http_request_url_get(log, r);
	ck_assert_str_eq(url, "https://www.example.com");
	oauth2_mem_free(url);

	// test deleting first header
	oauth2_http_request_header_set(log, r, "Host", NULL);
	url = oauth2_http_request_url_get(log, r);
	ck_assert_ptr_eq(url, NULL);

	oauth2_http_request_free(log, r);
}
END_TEST

START_TEST(test_query_encode)
{
	oauth2_nv_list_t *args = NULL;
	char *url = NULL, *enc = NULL;

	args = oauth2_nv_list_init(log);

	enc = oauth2_http_url_query_encode(log, NULL, args);
	ck_assert_str_eq(enc, "");
	oauth2_mem_free(enc);

	url = "https://www.example.com";
	enc = oauth2_http_url_query_encode(log, url, args);
	ck_assert_str_eq(enc, "https://www.example.com");
	oauth2_mem_free(enc);

	url = "https://www.example.com";
	oauth2_nv_list_add(log, args, "two", "TWO TWO");
	enc = oauth2_http_url_query_encode(log, url, args);
	ck_assert_str_eq(enc, "https://www.example.com?two=TWO%20TWO");
	oauth2_mem_free(enc);

	url = "https://www.example.com?one=ONE";
	enc = oauth2_http_url_query_encode(log, url, args);
	ck_assert_str_eq(enc, "https://www.example.com?one=ONE&two=TWO%20TWO");
	oauth2_mem_free(enc);

	url = "https://www.example.com";
	oauth2_nv_list_add(log, args, "none", NULL);
	enc = oauth2_http_url_query_encode(log, url, args);
	ck_assert_str_eq(enc, "https://www.example.com?two=TWO%20TWO&none=");
	oauth2_mem_free(enc);

	oauth2_nv_list_free(log, args);
}
END_TEST

START_TEST(test_form_encode)
{
	oauth2_nv_list_t *args = NULL;
	char *enc = NULL;

	args = oauth2_nv_list_init(log);

	enc = oauth2_http_url_form_encode(log, args);
	ck_assert_ptr_eq(enc, NULL);

	oauth2_nv_list_add(log, args, "two", "TWO TWO");
	enc = oauth2_http_url_form_encode(log, args);
	ck_assert_str_eq(enc, "two=TWO%20TWO");
	oauth2_mem_free(enc);

	oauth2_nv_list_add(log, args, "three", "THREE&THREE");
	enc = oauth2_http_url_form_encode(log, args);
	ck_assert_str_eq(enc, "two=TWO%20TWO&three=THREE%26THREE");
	oauth2_mem_free(enc);

	oauth2_nv_list_free(log, args);
}
END_TEST

static char *get_json = "{ \"my\": \"json\" }";
static char *get_json_path = "/my_json";

static char *oauth2_check_http_serve_get(const char *request)
{
	if (strncmp(request, get_json_path, strlen(get_json_path)) == 0) {
		return oauth2_strdup(get_json);
	}
	return oauth2_strdup("problem");
}

static char *post_json = "{ \"form\": \"post\" }";
static char *post_form_json_path = "/post_json";

static char *oauth2_check_http_serve_post(const char *request)
{
	if (strncmp(request, post_form_json_path,
		    strlen(post_form_json_path)) == 0) {
		return oauth2_strdup(post_json);
	}
	return oauth2_strdup("problem");
}

OAUTH2_CHECK_HTTP_PATHS

START_TEST(test_http_get)
{
	bool rc;
	char *response = NULL, *url = NULL;
	oauth2_nv_list_t *params = oauth2_nv_list_init(log);
	oauth2_http_call_ctx_t *ctx = oauth2_http_call_ctx_init(log);

	url = oauth2_stradd(NULL, oauth2_check_http_base_url(), get_json_path,
			    NULL);
	rc = oauth2_http_get(log, url, NULL, NULL, NULL, NULL);
	ck_assert_int_eq(rc, false);

	rc = oauth2_http_get(log, url, NULL, NULL, &response, NULL);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(response, get_json);
	oauth2_mem_free(response);

	oauth2_http_call_ctx_basic_auth_set(log, ctx, "hans:ja", "my secret",
					    true);
	oauth2_http_call_ctx_cookie_add(log, ctx, "mycookie", "mycvalue");
	oauth2_http_call_ctx_cookie_add(log, ctx, "othercookie", "my2ndvalue");
	oauth2_http_call_ctx_hdr_add(log, ctx, "SM_SESSION", "something");

	oauth2_nv_list_add(log, params, "jan", "piet");
	rc = oauth2_http_get(log, url, params, ctx, &response, NULL);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(response, get_json);
	oauth2_mem_free(response);

	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
	oauth2_mem_free(url);
}
END_TEST

START_TEST(test_http_post_form)
{
	bool rc;
	char *response = NULL, *url = NULL;
	oauth2_nv_list_t *params = oauth2_nv_list_init(log);

	url = oauth2_stradd(NULL, oauth2_check_http_base_url(),
			    post_form_json_path, NULL);
	oauth2_nv_list_add(log, params, "jan", "piet");
	rc = oauth2_http_post_form(log, url, params, NULL, &response, NULL);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(response, post_json);
	oauth2_mem_free(response);

	oauth2_nv_list_free(log, params);
	oauth2_mem_free(url);
}
END_TEST

START_TEST(test_cookies)
{
	bool rc = false;
	oauth2_http_request_t *r = NULL;
	char *rv = NULL;
	const char *rvv = NULL;
	oauth2_nv_list_t *params = NULL;

	params = NULL;
	rc = oauth2_parse_form_encoded_params(
	    log, "jan=piet&klaas=vaak&hans=zandbelt", &params);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(params, NULL);
	oauth2_nv_list_free(log, params);

	r = oauth2_http_request_init(log);
	oauth2_http_request_header_set(log, r, "Host", "www.example.com");
	oauth2_http_request_header_set(log, r, "Cookie",
				       "jan=piet; klaas=vaak; hans=zandbelt");

	rv = oauth2_http_request_cookie_get(log, r, "klaas", false);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_str_eq(rv, "vaak");
	oauth2_mem_free(rv);

	rv = oauth2_http_request_cookie_get(log, r, "klaas", true);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_str_eq(rv, "vaak");
	oauth2_mem_free(rv);

	rv = oauth2_http_request_cookie_get(log, r, "klaas", true);
	ck_assert_ptr_eq(rv, NULL);

	rvv = oauth2_http_request_header_get(log, r, "Cookie");
	ck_assert_ptr_ne(rvv, NULL);
	ck_assert_str_eq(rvv, "jan=piet; hans=zandbelt");

	oauth2_http_request_free(log, r);
}
END_TEST

START_TEST(test_auth)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = oauth2_http_call_ctx_init(log);

	rc = oauth2_http_auth_client_cert(log, "cert.pem", "key.pem", ctx);
	ck_assert_int_eq(rc, true);

	rc = oauth2_http_auth_basic(log, "myusername", "mypassword", ctx);
	ck_assert_int_eq(rc, true);

	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

START_TEST(test_xml_http_request)
{
	bool rc = false;
	oauth2_http_request_t *r = NULL;

	r = oauth2_http_request_init(log);

	rc = oauth2_http_request_header_set(log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_is_xml_http_request(log, r);
	ck_assert_int_eq(rc, false);

	rc = oauth2_http_request_header_set(log, r, "Accept",
					    "application/json");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_is_xml_http_request(log, r);
	ck_assert_int_eq(rc, true);

	rc = oauth2_http_request_header_set(log, r, "Accept", "*/*");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_is_xml_http_request(log, r);
	ck_assert_int_eq(rc, false);

	rc = oauth2_http_request_header_set(log, r, "X-Requested-With",
					    "XMLHttpRequest");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(
	    log, r, "Accept",
	    "text/html, application/xhtml+xml, application/xml;q=0.9, "
	    "image/webp, */*;q=0.8");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_is_xml_http_request(log, r);
	ck_assert_int_eq(rc, true);

	oauth2_http_request_free(log, r);
}
END_TEST

Suite *oauth2_check_http_suite()
{
	Suite *s = suite_create("http");
	TCase *c = tcase_create("core");

	liboauth2_check_register_http_callbacks(oauth2_check_http_base_path(),
						oauth2_check_http_serve_get,
						oauth2_check_http_serve_post);

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_request_scheme);
	tcase_add_test(c, test_request_hostname);
	tcase_add_test(c, test_request_port);
	tcase_add_test(c, test_url_base);
	tcase_add_test(c, test_url_get);
	tcase_add_test(c, test_request_header);
	tcase_add_test(c, test_query_encode);
	tcase_add_test(c, test_form_encode);
	tcase_add_test(c, test_http_get);
	tcase_add_test(c, test_http_post_form);
	tcase_add_test(c, test_cookies);
	tcase_add_test(c, test_auth);
	tcase_add_test(c, test_xml_http_request);

	suite_add_tcase(s, c);

	return s;
}
