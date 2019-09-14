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
#include "oauth2/mem.h"
#include "oauth2/openidc.h"
#include "oauth2/util.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *log = 0;

static void setup(void)
{
	log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(log);
}

START_TEST(test_openidc_cfg)
{
	bool rc = false;
	oauth2_cfg_openidc_t *c = NULL;
	oauth2_http_request_t *r = NULL;
	oauth2_openidc_provider_t *p = NULL;
	char *value = NULL;

	c = oauth2_cfg_openidc_init(log);
	r = oauth2_http_request_init(log);

	rc = oauth2_cfg_openidc_redirect_uri_set(
	    log, c, "https://example.org/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.org/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_cfg_openidc_redirect_uri_set(
	    log, c, "https://example.com/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_cfg_openidc_redirect_uri_set(log, c, "/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_http_request_header_set(log, r, "Host", "example.com");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	p = oauth2_openidc_provider_init(log);
	ck_assert_ptr_ne(p, NULL);

	value = oauth2_cfg_openidc_redirect_uri_get_iss(log, c, r, p);
	// ck_assert_ptr_eq(value, NULL);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_openidc_provider_issuer_set(log, p, "jan");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get_iss(log, c, r, p);
	ck_assert_str_eq(value, "https://example.com/redirect_uri?iss=jan");
	oauth2_mem_free(value);

	oauth2_openidc_provider_free(log, p);
	oauth2_http_request_free(log, r);
	oauth2_cfg_openidc_free(log, c);
}
END_TEST

bool test_openidc_provider_resolver(oauth2_log_t *log,
				    const oauth2_http_request_t *request,
				    oauth2_openidc_provider_t **provider)
{
	// TODO: free/global
	*provider = oauth2_openidc_provider_init(log);
	oauth2_openidc_provider_issuer_set(log, *provider,
					   "https://op.example.org");
	oauth2_openidc_provider_authorization_endpoint_set(
	    log, *provider, "https://op.example.org/authorize");
	oauth2_openidc_provider_scope_set(log, *provider, "openid");
	oauth2_openidc_provider_client_id_set(log, *provider, "myclient");
	oauth2_openidc_provider_client_secret_set(log, *provider, "secret");
	return true;
}

START_TEST(test_openidc_handle)
{
	bool rc = false;
	oauth2_cfg_openidc_t *c = NULL;
	oauth2_http_request_t *r = NULL;
	oauth2_http_response_t *response = NULL;
	const char *metadata =
	    "{ "
	    "\"issuer\": \"https://op.example.org\","
	    "\"authorization_endpoint\": \"https://op.example.org/authorize\","
	    "\"token_endpoint\": \"https://op.example.org/token\","
	    "\"token_endpoint_auth\": \"client_secret_post\","
	    "\"client_id\": \"myclient\","
	    "\"client_secret\": \"secret1234\","
	    "\"scope\": \"openid profile\","
	    "\"ssl_verify\": false"
	    "}";
	c = oauth2_cfg_openidc_init(log);
	r = oauth2_http_request_init(log);

	oauth2_cfg_openidc_passphrase_set(log, c, "mypassphrase1234");
	oauth2_cfg_openidc_provider_resolver_set_options(log, c, "string",
							 metadata, NULL);

	rc = oauth2_http_request_path_set(log, r, "/secure");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);

	rc = oauth2_openidc_handle(log, c, r, &response);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, response);

	ck_assert_uint_eq(oauth2_http_response_status_code_get(log, response),
			  302);
	ck_assert_ptr_ne(NULL, strstr(oauth2_http_response_header_get(
					  log, response, "Location"),
				      "response_type=code"));
	ck_assert_ptr_ne(NULL, strstr(oauth2_http_response_header_get(
					  log, response, "Location"),
				      "https://op.example.org/authorize"));
	ck_assert_ptr_ne(NULL, strstr(oauth2_http_response_header_get(
					  log, response, "Set-Cookie"),
				      "openidc_state_"));

	oauth2_http_response_free(log, response);
	response = NULL;
	oauth2_http_request_free(log, r);

	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_path_set(log, r,
					  "/openid-connect/redirect_uri");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_query_set(log, r, "code=4321&state=7654");
	ck_assert_int_eq(rc, true);

	rc = oauth2_openidc_handle(log, c, r, &response);
	// TODO:
	// ck_assert_int_eq(rc, true);
	// ck_assert_ptr_ne(NULL, response);
	// ck_assert_uint_eq(oauth2_http_response_status_code_get(log,
	// response), 200);

	oauth2_http_response_free(log, response);
	oauth2_http_request_free(log, r);

	oauth2_cfg_openidc_free(log, c);
}
END_TEST

Suite *oauth2_check_openidc_suite()
{
	Suite *s = suite_create("openidc");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_openidc_cfg);
	tcase_add_test(c, test_openidc_handle);

	suite_add_tcase(s, c);

	return s;
}
