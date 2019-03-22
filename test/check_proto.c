/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone IT BV - www.zmartzone.eu
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

#include "oauth2/mem.h"
#include "oauth2/proto.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *log = 0;

static void setup(void)
{
	log = oauth2_log_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_log_free(log);
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
	*params = oauth2_nv_list_init(log);
	oauth2_nv_list_add(log, *params, my_token_name, my_post_token);
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

	request = oauth2_http_request_init(log);

	cfg = oauth2_cfg_source_token_init(log);
	ck_assert_ptr_ne(cfg, NULL);
	token = oauth2_get_source_token(log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_env_var_token);
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(log, cfg);

	oauth2_http_request_free(log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_header)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(log);

	cfg = oauth2_cfg_source_token_init(log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(log, cfg, "header", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_hdr_in_set(log, request, "Authorization",
				       "bearer my_header_token");
	token = oauth2_get_source_token(log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_header_token");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(log, cfg);

	oauth2_http_request_free(log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_query)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(log);

	cfg = oauth2_cfg_source_token_init(log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(log, cfg, "query", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_query_set(log, request,
				      "access_token=my_query_token");
	token = oauth2_get_source_token(log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_query_token");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(log, cfg);

	oauth2_http_request_free(log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_cookie)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(log);

	cfg = oauth2_cfg_source_token_init(log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(log, cfg, "cookie", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_cookie_set(log, request, "access_token",
				       "my_cookie_token");
	token = oauth2_get_source_token(log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_cookie_token");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(log, cfg);

	oauth2_http_request_free(log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_post)
{
	const char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(log);
	oauth2_http_request_method_set(log, request, OAUTH2_HTTP_METHOD_POST);
	oauth2_http_request_hdr_in_set(log, request, "Content-Type",
				       "application/x-www-form-urlencoded");

	cfg = oauth2_cfg_source_token_init(log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(log, cfg, "post", NULL);
	ck_assert_ptr_eq(rv, NULL);
	token = oauth2_get_source_token(log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, my_post_token);
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(log, cfg);

	oauth2_http_request_free(log, request);
}
END_TEST

START_TEST(test_proto_get_source_token_basic)
{
	char *rv = NULL;
	char *token = NULL;
	oauth2_cfg_source_token_t *cfg = NULL;
	oauth2_http_request_t *request = NULL;

	request = oauth2_http_request_init(log);

	cfg = oauth2_cfg_source_token_init(log);
	ck_assert_ptr_ne(cfg, NULL);
	rv = oauth2_cfg_source_token_set_accept_in(log, cfg, "basic", NULL);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_http_request_hdr_in_set(log, request, "Authorization",
				       "Basic ZHVtbXk6bXlfYmFzaWNfdG9rZW4=");
	token = oauth2_get_source_token(log, cfg, request,
					&_oauth2_check_proto_callbacks, NULL);
	ck_assert_ptr_ne(token, NULL);
	ck_assert_str_eq(token, "my_basic_token");
	oauth2_mem_free(token);
	oauth2_cfg_source_token_free(log, cfg);

	oauth2_http_request_free(log, request);
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

	suite_add_tcase(s, c);

	return s;
}
