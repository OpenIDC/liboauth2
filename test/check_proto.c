/***************************************************************************
 *
 * Copyright (C) 2018-2020 - ZmartZone Holding BV - www.zmartzone.eu
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
#include "oauth2/proto.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *_log = 0;

static void setup(void)
{
	_log = oauth2_log_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_log_free(_log);
}

static const char *my_token_name = "access_token";
static const char *my_env_var_token = "my_env_var_token";
static const char *my_post_token = "my_post_token";

static bool _oauth2_check_proto_env_get_cb(oauth2_log_t *log, void *ctx,
					   const char *name, char **value)
{
	if (strcmp(name, my_token_name) == 0)
		*value = oauth2_strdup(my_env_var_token);
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
	return true;
}

static oauth2_cfg_server_callback_funcs_t _oauth2_check_proto_callbacks = {
    _oauth2_check_proto_env_get_cb, _oauth2_check_proto_env_set_cb,
    _oauth2_check_proto_read_form_post};

START_TEST(test_proto_get_source_token_environment)
{
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(_log);

	cfg = oauth2_cfg_source_token_init(_log);
	ck_assert_ptr_ne(cfg, NULL);
	token = oauth2_get_source_token(_log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_env_var_token);
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(_log, cfg);

	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_header)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
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
	oauth2_cfg_source_token_free(_log, cfg);

	oauth2_http_request_free(_log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_query)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
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
	oauth2_cfg_source_token_free(_log, cfg);

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

OAUTH2_CHECK_HTTP_PATHS

static char *token_endpoint_path = "/token";

static char *ropc_result_json = "{ \"access_token\": \"my_ropc_token\" }";

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
	char *options = NULL;

	options = oauth2_stradd(NULL, "url=", oauth2_check_http_base_url(),
				token_endpoint_path);

	cfg = oauth2_cfg_ropc_init(_log);
	rv = oauth2_cfg_set_ropc_options(_log, cfg, options);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_ropc_exec(_log, cfg, "joe", "2Federate", &token,
			      &status_code);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(token, "my_ropc_token");

	oauth2_mem_free(token);
	oauth2_cfg_ropc_free(_log, cfg);
	oauth2_mem_free(options);
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

	suite_add_tcase(s, c);

	return s;
}
