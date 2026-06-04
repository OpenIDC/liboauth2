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

#include "check_liboauth2.h"
#include "http_server.h"
#include "oauth2/mem.h"
#include "oauth2/proto.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *_log = 0;

void oauth2_check_proto_cleanup()
{
}

static void setup(void)
{
	_log = oauth2_log_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_log_free(_log);
}

static const char *my_token_name = "access_token";
static const char *my_token_name2 = "access_token2";
static const char *my_env_var_token = "my_env_var_token";
static const char *my_env_var_token2 = "my_env_var_token2";
static const char *my_post_token = "my_post_token";
static const char *my_post_token2 = "my_post_token2";

static bool _oauth2_check_proto_env_get_cb(oauth2_log_t *log, void *ctx,
					   const char *name, char **value)
{
	if (strcmp(name, my_token_name) == 0)
		*value = oauth2_strdup(my_env_var_token);
	if (strcmp(name, my_token_name2) == 0)
		*value = oauth2_strdup(my_env_var_token2);
	return true;
}

static bool _oauth2_check_proto_env_set_cb(oauth2_log_t *log, void *ctx,
					   const char *name, const char *value)
{
	return true;
}

static bool _oauth2_check_proto_read_form_post(oauth2_log_t *log, void *ctx,
					       oauth2_nv_list_t **params)
{
	*params = oauth2_nv_list_init(_log);
	oauth2_nv_list_add(_log, *params, my_token_name, my_post_token);
	oauth2_nv_list_add(_log, *params, my_token_name2, my_post_token2);
	return true;
}

static oauth2_cfg_server_callback_funcs_t _oauth2_check_proto_callbacks = {
    _oauth2_check_proto_env_get_cb, _oauth2_check_proto_env_set_cb,
    _oauth2_check_proto_read_form_post};

START_TEST(test_proto_get_source_token_environment)
{
	char *token = NULL;
	char *rv = NULL;
	oauth2_cfg_source_token_t *cfg = NULL, *cfg2 = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(_log);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_env_var_token);
	oauth2_mem_free(token);

	cfg2 = oauth2_cfg_source_token_clone(_log, cfg);
	oauth2_cfg_source_token_free(_log, cfg);

	rv = oauth2_cfg_source_token_set_accept_in(_log, NULL, NULL, NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	rv = oauth2_cfg_token_in_set(_log, NULL, NULL, NULL,
				     OAUTH2_CFG_TOKEN_IN_ENVVAR);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg2, "bogus", NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	rv = oauth2_cfg_source_token_set_accept_in(
	    _log, cfg2, "environment", "name=access_token2&strip=false");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(oauth2_cfg_source_token_get_strip(cfg2), false);
	token = oauth2_get_source_token(_log, cfg2, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_env_var_token2);
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg2);

	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_header)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL, *cfg2 = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(_log);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "header", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_header_set(_log, request, "Authorization",
				       "bearer my_header_token");
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_header_token");
	oauth2_mem_free(token);

	cfg2 = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg2, NULL);
	oauth2_cfg_source_token_merge(_log, cfg2, NULL, cfg);
	oauth2_cfg_source_token_free(_log, cfg);

	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg2, "header",
						   "type=other&name=MyHeader");
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_header_set(_log, request, "MyHeader",
				       "other my_other_token");
	token = oauth2_get_source_token(_log, cfg2, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_other_token");
	oauth2_mem_free(token);

	oauth2_cfg_source_token_free(_log, cfg2);

	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_query)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL, *cfg2 = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(_log);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "query", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_query_set(_log, request,
				      "access_token=my_query_token");
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_query_token");
	oauth2_mem_free(token);
	oauth2_http_request_free(_log, request);

	cfg2 = oauth2_cfg_source_token_clone(_log, cfg);
	oauth2_cfg_source_token_free(_log, cfg);

	request = oauth2_http_request_init(_log);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg2, "query",
						   "name=access_token2");
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_query_set(_log, request,
				      "access_token2=my_query_token2");
	token = oauth2_get_source_token(_log, cfg2, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_query_token2");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg2);
	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_cookie)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(_log);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "cookie", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_cookie_set(_log, request, "access_token",
				       "my_cookie_token");
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_cookie_token");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "cookie",
						   "name=access_token_cookie");
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_cookie_set(_log, request, "access_token_cookie",
				       "my_cookie_token2");
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_cookie_token2");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg);

	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_post)
{
	const char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(_log);
	oauth2_http_request_method_set(_log, request, OAUTH2_HTTP_METHOD_POST);
	oauth2_http_request_header_set(_log, request, "Content-Type",
				       "application/x-www-form-urlencoded");

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "post", NULL);
	ck_assert_ptr_eq(rv, NULL);
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_post_token);
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "post",
						   "name=access_token2");
	ck_assert_ptr_eq(rv, NULL);
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_post_token2);
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg);

	oauth2_http_request_free(_log, request);

	// also test for "application/x-www-form-urlencoded;charset=UTF-8" etc.;
	// see #72

	request = oauth2_http_request_init(_log);
	oauth2_http_request_method_set(_log, request, OAUTH2_HTTP_METHOD_POST);
	oauth2_http_request_header_set(
	    _log, request, "Content-Type",
	    "application/x-www-form-urlencoded;charset=UTF-8");

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "post", NULL);
	ck_assert_ptr_eq(rv, NULL);
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_post_token);
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg);

	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_basic)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(_log);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(_log, cfg, "basic", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_header_set(_log, request, "Authorization",
				       "Basic ZHVtbXk6bXlfYmFzaWNfdG9rZW4=");
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_basic_token");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg);

	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_ropc)
{
	bool rc = false;
	oauth2_cfg_ropc_t *cfg = NULL;
	char *token = NULL;
	oauth2_uint_t status_code = 0;
	char *rv = NULL;
	char *url = NULL;
	oauth2_check_http_response_t resp = {
	    .status_code = 200,
	    .content_type = "application/json",
	    .body = "{ \"access_token\": \"my_ropc_token\" }"};
	oauth2_check_http_server_t *srv = NULL;
	const oauth2_check_http_captured_t *cap = NULL;

	srv = oauth2_check_http_server_start(&resp);
	ck_assert_ptr_ne(srv, NULL);

	url = oauth2_stradd(NULL, oauth2_check_http_server_url(srv), "/token",
			    NULL);

	cfg = oauth2_cfg_ropc_init(_log);
	rv = oauth2_cfg_set_ropc(_log, cfg, url, NULL);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_ropc_exec(_log, cfg, "joe", "2Federate", &token,
			      &status_code);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(token, "my_ropc_token");

	cap = oauth2_check_http_server_wait(srv);
	ck_assert_ptr_ne(cap, NULL);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_ptr_ne(strstr(cap->body, "grant_type=password"), NULL);

	oauth2_check_http_server_stop(srv);
	oauth2_mem_free(token);
	oauth2_cfg_ropc_free(_log, cfg);
	oauth2_mem_free(url);
}
END_TEST

START_TEST(test_proto_cc)
{
	bool rc = false;
	oauth2_cfg_cc_t *cfg = NULL;
	char *token = NULL;
	oauth2_uint_t status_code = 0;
	char *rv = NULL;
	char *url = NULL;
	oauth2_check_http_response_t resp = {
	    .status_code = 200,
	    .content_type = "application/json",
	    .body = "{ \"access_token\": \"my_cc_token\" }"};
	oauth2_check_http_server_t *srv = NULL;
	const oauth2_check_http_captured_t *cap = NULL;

	srv = oauth2_check_http_server_start(&resp);
	ck_assert_ptr_ne(srv, NULL);

	url = oauth2_stradd(NULL, oauth2_check_http_server_url(srv), "/token",
			    NULL);

	cfg = oauth2_cfg_cc_init(_log);
	rv = oauth2_cfg_set_cc(_log, cfg, url, NULL);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_cc_exec(_log, cfg, &token, &status_code);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(token, "my_cc_token");

	cap = oauth2_check_http_server_wait(srv);
	ck_assert_ptr_ne(cap, NULL);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_ptr_ne(strstr(cap->body, "grant_type=client_credentials"),
			 NULL);

	oauth2_check_http_server_stop(srv);
	oauth2_mem_free(token);
	oauth2_cfg_cc_free(_log, cfg);
	oauth2_mem_free(url);
}
END_TEST

START_TEST(test_proto_cfg_endpoint)
{
	char *rv = NULL;
	oauth2_cfg_endpoint_t *cfg = NULL, *clone = NULL;
	oauth2_nv_list_t *params = NULL;

	// NULL guards
	oauth2_cfg_endpoint_free(_log, NULL);
	clone = oauth2_cfg_endpoint_clone(_log, NULL);
	ck_assert_ptr_eq(clone, NULL);
	rv = oauth2_cfg_set_endpoint(_log, NULL, "http://example.com", NULL,
				     NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	// url taken from params, plus every endpoint option
	cfg = oauth2_cfg_endpoint_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	oauth2_parse_form_encoded_params(
	    _log,
	    "url=http%3A%2F%2Fexample.com%2Ftoken&http_timeout=30&http_retries="
	    "2&http_retry_interval=60&outgoing_proxy=http%3A%2F%2Fproxy%3A3128&"
	    "ssl_verify=false",
	    &params);
	rv = oauth2_cfg_set_endpoint(_log, cfg, NULL, params, NULL);
	ck_assert_ptr_eq(rv, NULL);

	ck_assert_str_eq(oauth2_cfg_endpoint_get_url(cfg),
			 "http://example.com/token");
	ck_assert_uint_eq(oauth2_cfg_endpoint_get_http_timeout(cfg), 30);
	ck_assert_uint_eq(oauth2_cfg_endpoint_get_http_retries(cfg), 2);
	ck_assert_uint_eq(oauth2_cfg_endpoint_get_http_retry_interval(cfg), 60);
	ck_assert_str_eq(oauth2_cfg_endpoint_get_outgoing_proxy(cfg),
			 "http://proxy:3128");
	ck_assert_uint_eq(oauth2_cfg_endpoint_get_ssl_verify(cfg), false);

	// clone (copies the outgoing_proxy too) then free both
	clone = oauth2_cfg_endpoint_clone(_log, cfg);
	ck_assert_ptr_ne(clone, NULL);
	ck_assert_str_eq(oauth2_cfg_endpoint_get_outgoing_proxy(clone),
			 "http://proxy:3128");

	oauth2_nv_list_free(_log, params);
	oauth2_cfg_endpoint_free(_log, clone);
	oauth2_cfg_endpoint_free(_log, cfg);
}
END_TEST

START_TEST(test_proto_ropc_cfg)
{
	char *rv = NULL;
	oauth2_cfg_ropc_t *cfg = NULL, *cfg2 = NULL, *cfg3 = NULL;

	// NULL cfg guard
	rv = oauth2_cfg_set_ropc(_log, NULL, "http://example.com/token", NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	// auth options + endpoint options through the same setter
	cfg = oauth2_cfg_ropc_init(_log);
	rv = oauth2_cfg_set_ropc(_log, cfg, "http://example.com/token",
				 "client_id=myclient&username=joe&password="
				 "secret&params=scope%3Dopenid&http_timeout=30&"
				 "outgoing_proxy=http%3A%2F%2Fproxy%3A3128");
	ck_assert_ptr_eq(rv, NULL);

	ck_assert_ptr_ne(oauth2_cfg_ropc_get_token_endpoint(cfg), NULL);
	ck_assert_str_eq(oauth2_cfg_ropc_get_client_id(cfg), "myclient");
	ck_assert_str_eq(oauth2_cfg_ropc_get_username(cfg), "joe");
	ck_assert_str_eq(oauth2_cfg_ropc_get_password(cfg), "secret");
	ck_assert_ptr_ne(oauth2_cfg_ropc_get_request_parameters(cfg), NULL);

	// NULL-cfg accessor branches
	ck_assert_ptr_eq(oauth2_cfg_ropc_get_token_endpoint(NULL), NULL);
	(void)oauth2_cfg_ropc_get_client_id(NULL);
	(void)oauth2_cfg_ropc_get_username(NULL);
	(void)oauth2_cfg_ropc_get_password(NULL);
	ck_assert_ptr_eq(oauth2_cfg_ropc_get_request_parameters(NULL), NULL);

	// clone + clone(NULL)
	cfg2 = oauth2_cfg_ropc_clone(_log, cfg);
	ck_assert_ptr_ne(cfg2, NULL);
	ck_assert_str_eq(oauth2_cfg_ropc_get_client_id(cfg2), "myclient");
	ck_assert_ptr_eq(oauth2_cfg_ropc_clone(_log, NULL), NULL);

	// merge null guards + a real merge into a fresh (all-NULL) dst
	cfg3 = oauth2_cfg_ropc_init(_log);
	oauth2_cfg_ropc_merge(_log, NULL, NULL, NULL);
	oauth2_cfg_ropc_merge(_log, cfg3, NULL, NULL);
	oauth2_cfg_ropc_merge(_log, cfg3, cfg, cfg2);
	ck_assert_str_eq(oauth2_cfg_ropc_get_client_id(cfg3), "myclient");

	oauth2_cfg_ropc_free(_log, cfg);
	oauth2_cfg_ropc_free(_log, cfg2);
	oauth2_cfg_ropc_free(_log, cfg3);
}
END_TEST

START_TEST(test_proto_cc_cfg)
{
	char *rv = NULL;
	oauth2_cfg_cc_t *cfg = NULL, *cfg2 = NULL, *cfg3 = NULL;

	// NULL cfg guard
	rv = oauth2_cfg_set_cc(_log, NULL, "http://example.com/token", NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	cfg = oauth2_cfg_cc_init(_log);
	rv = oauth2_cfg_set_cc(_log, cfg, "http://example.com/token",
			       "client_id=myclient&params=scope%3Dopenid&http_"
			       "timeout=45&outgoing_proxy=http%3A%2F%2Fproxy%"
			       "3A3128&ssl_verify=true");
	ck_assert_ptr_eq(rv, NULL);

	ck_assert_ptr_ne(oauth2_cfg_cc_get_token_endpoint(cfg), NULL);
	ck_assert_str_eq(oauth2_cfg_cc_get_client_id(cfg), "myclient");
	ck_assert_ptr_ne(oauth2_cfg_cc_get_request_parameters(cfg), NULL);

	// NULL-cfg accessor branches
	ck_assert_ptr_eq(oauth2_cfg_cc_get_token_endpoint(NULL), NULL);
	(void)oauth2_cfg_cc_get_client_id(NULL);
	ck_assert_ptr_eq(oauth2_cfg_cc_get_request_parameters(NULL), NULL);

	// clone + clone(NULL)
	cfg2 = oauth2_cfg_cc_clone(_log, cfg);
	ck_assert_ptr_ne(cfg2, NULL);
	ck_assert_str_eq(oauth2_cfg_cc_get_client_id(cfg2), "myclient");
	ck_assert_ptr_eq(oauth2_cfg_cc_clone(_log, NULL), NULL);

	// merge null guards + a real merge into a fresh dst
	cfg3 = oauth2_cfg_cc_init(_log);
	oauth2_cfg_cc_merge(_log, NULL, NULL, NULL);
	oauth2_cfg_cc_merge(_log, cfg3, NULL, NULL);
	oauth2_cfg_cc_merge(_log, cfg3, cfg, cfg2);
	ck_assert_str_eq(oauth2_cfg_cc_get_client_id(cfg3), "myclient");

	oauth2_cfg_cc_free(_log, cfg);
	oauth2_cfg_cc_free(_log, cfg2);
	oauth2_cfg_cc_free(_log, cfg3);
}
END_TEST

Suite *oauth2_check_proto_suite()
{
	Suite *s = suite_create("proto");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_proto_get_source_token_environment);
	tcase_add_test(c, test_proto_get_source_token_header);
	tcase_add_test(c, test_proto_get_source_token_query);
	tcase_add_test(c, test_proto_get_source_token_cookie);
	tcase_add_test(c, test_proto_get_source_token_post);
	tcase_add_test(c, test_proto_get_source_token_basic);
	tcase_add_test(c, test_proto_ropc);
	tcase_add_test(c, test_proto_cc);
	tcase_add_test(c, test_proto_cfg_endpoint);
	tcase_add_test(c, test_proto_ropc_cfg);
	tcase_add_test(c, test_proto_cc_cfg);

	suite_add_tcase(s, c);

	return s;
}
