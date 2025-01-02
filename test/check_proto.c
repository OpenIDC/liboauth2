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
#include "oauth2/mem.h"
#include "oauth2/proto.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *_log = 0;

OAUTH2_CHECK_HTTP_PATHS

void oauth2_check_proto_cleanup()
{
	oauth2_check_http_base_free();
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

static char *token_endpoint_path = "/token";

static char *ropc_result_json = "{ \"access_token\": \"my_ropc_token\" }";
static char *cc_result_json = "{ \"access_token\": \"my_cc_token\" }";

static char *oauth2_check_proto_serve_post(const char *request)
{
	oauth2_nv_list_t *params = NULL;
	char *data = NULL;
	const char *grant_type = NULL;
	const char *sep = "****";
	char *rv = NULL;

	if (strncmp(request, token_endpoint_path,
		    strlen(token_endpoint_path)) == 0) {
		request += strlen(token_endpoint_path) + 5;
		data = strstr(request, sep);
		if (data == NULL)
			goto error;
		data += strlen(sep);
		if (oauth2_parse_form_encoded_params(_log, data, &params) ==
		    false)
			goto error;
		grant_type = oauth2_nv_list_get(_log, params, "grant_type");
		if (grant_type == NULL)
			goto error;
		if ((grant_type) && (strcmp(grant_type, "password") == 0)) {
			// TODO: check username password
			rv = oauth2_strdup(ropc_result_json);
		} else if ((grant_type) &&
			   (strcmp(grant_type, "client_credentials") == 0)) {
			rv = oauth2_strdup(cc_result_json);
		} else {
			rv = oauth2_strdup(
			    "{ \"error\": \"unsupported grant_type\" }");
		}
		oauth2_nv_list_free(_log, params);
		goto end;
	}

error:

	rv = oauth2_strdup("problem");

end:

	return rv;
}

START_TEST(test_proto_ropc)
{
	bool rc = false;
	oauth2_cfg_ropc_t *cfg = NULL;
	char *token = NULL;
	oauth2_uint_t status_code = 0;
	char *rv = NULL;
	char *url = NULL;

	url = oauth2_stradd(NULL, NULL, oauth2_check_http_base_url(),
			    token_endpoint_path);

	cfg = oauth2_cfg_ropc_init(_log);
	rv = oauth2_cfg_set_ropc(_log, cfg, url, NULL);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_ropc_exec(_log, cfg, "joe", "2Federate", &token,
			      &status_code);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(token, "my_ropc_token");

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

	url = oauth2_stradd(NULL, NULL, oauth2_check_http_base_url(),
			    token_endpoint_path);

	cfg = oauth2_cfg_cc_init(_log);
	rv = oauth2_cfg_set_cc(_log, cfg, url, NULL);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_cc_exec(_log, cfg, &token, &status_code);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(token, "my_cc_token");

	oauth2_mem_free(token);
	oauth2_cfg_cc_free(_log, cfg);
	oauth2_mem_free(url);
}
END_TEST

Suite *oauth2_check_proto_suite()
{
	Suite *s = suite_create("proto");
	TCase *c = tcase_create("core");

	liboauth2_check_register_http_callbacks(
	    oauth2_check_http_base_path(), NULL, oauth2_check_proto_serve_post);

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_proto_get_source_token_environment);
	tcase_add_test(c, test_proto_get_source_token_header);
	tcase_add_test(c, test_proto_get_source_token_query);
	tcase_add_test(c, test_proto_get_source_token_cookie);
	tcase_add_test(c, test_proto_get_source_token_post);
	tcase_add_test(c, test_proto_get_source_token_basic);
	tcase_add_test(c, test_proto_ropc);
	tcase_add_test(c, test_proto_cc);

	suite_add_tcase(s, c);

	return s;
}
