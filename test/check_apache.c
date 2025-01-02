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

#include "oauth2/apache.h"
#include "oauth2/mem.h"

#include <check.h>

static apr_pool_t *pool = NULL;
static request_rec *request = NULL;
static oauth2_log_t *_log = 0;

static request_rec *setup_request(apr_pool_t *pool)
{
	// const unsigned int kIdx = 0;
	// const unsigned int kEls = kIdx + 1;
	request_rec *request =
	    (request_rec *)apr_pcalloc(pool, sizeof(request_rec));

	request->pool = pool;

	request->headers_in = apr_table_make(request->pool, 0);
	request->headers_out = apr_table_make(request->pool, 0);
	request->err_headers_out = apr_table_make(request->pool, 0);

	apr_table_set(request->headers_in, "Host", "www.example.com");
	apr_table_set(request->headers_in, "OIDC_foo", "some-value");
	apr_table_set(request->headers_in, "Cookie",
		      "foo=bar; "
		      "oauth2_openidc_session"
		      "=0123456789abcdef; baz=zot");

	request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
	request->server->process =
	    apr_pcalloc(request->pool, sizeof(struct process_rec));
	request->server->process->pool = request->pool;
	request->connection =
	    apr_pcalloc(request->pool, sizeof(struct conn_rec));
	request->connection->bucket_alloc =
	    apr_bucket_alloc_create(request->pool);
	request->connection->local_addr =
	    apr_pcalloc(request->pool, sizeof(apr_sockaddr_t));

	apr_pool_userdata_set("https", "scheme", NULL, request->pool);
	request->server->server_hostname = "www.example.com";
	request->connection->local_addr->port = 443;
	request->unparsed_uri = "/bla?foo=bar&param1=value1";
	request->args = "foo=bar&param1=value1";
	apr_uri_parse(request->pool,
		      "https://www.example.com/bla?foo=bar&param1=value1",
		      &request->parsed_uri);
	/*
		auth_openidc_module.module_index = kIdx;
		oidc_cfg *cfg = oidc_create_server_config(request->pool,
	   request->server); cfg->provider.issuer = "https://idp.example.com";
		cfg->provider.authorization_endpoint_url =
				"https://idp.example.com/authorize";
		cfg->provider.scope = "openid";
		cfg->provider.client_id = "client_id";
		cfg->provider.token_binding_policy =
	   OIDC_TOKEN_BINDING_POLICY_OPTIONAL; cfg->redirect_uri =
	   "https://www.example.com/protected/";

		oidc_dir_cfg *d_cfg = oidc_create_dir_config(request->pool,
	   NULL);
	*/
	/*
		request->server->module_config = apr_pcalloc(request->pool,
				sizeof(ap_conf_vector_t *) * kEls);
		request->per_dir_config = apr_pcalloc(request->pool,
				sizeof(ap_conf_vector_t *) * kEls);
	*/
	/*
		ap_set_module_config(request->server->module_config,
	   &auth_openidc_module, cfg);
		ap_set_module_config(request->per_dir_config,
	   &auth_openidc_module, d_cfg);

		cfg->crypto_passphrase = "12345678901234567890123456789012";
		cfg->cache = &oidc_cache_shm;
		cfg->cache_cfg = NULL;
		cfg->cache_shm_size_max = 500;
		cfg->cache_shm_entry_size_max = 16384 + 255 + 17;
		cfg->cache_encrypt = 1;
		if (cfg->cache->post_config(request->server) != OK) {
			printf("cfg->cache->post_config failed!\n");
			exit(-1);
		}
	*/
	return request;
}

static void check_apache_log_request(oauth2_log_sink_t *sink,
				     const char *filename, unsigned long line,
				     const char *function,
				     oauth2_log_level_t level, const char *msg)
{
	oauth2_log(_log, filename, line, function, level, "%s", msg);
}

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);

	apr_initialize();
	apr_pool_create(&pool, NULL);
	request = setup_request(pool);
}

static void teardown(void)
{
	apr_pool_destroy(pool);
	apr_terminate();

	oauth2_shutdown(_log);
}

START_TEST(test_apache_request_state)
{
	json_error_t err;
	const char *s_claims = "{ \"sub\": \"joe\" }";
	json_t *in_claims = NULL, *out_claims = NULL;
	const char *key = "C";
	char *value = NULL;
	oauth2_apache_request_ctx_t *ctx = NULL;

	ctx = oauth2_apache_request_context(request, check_apache_log_request,
					    "check_apache");
	in_claims = json_loads(s_claims, 0, &err);

	oauth2_apache_request_state_set_json(ctx, key, in_claims);

	oauth2_apache_request_state_get_json(ctx, key, &out_claims);
	ck_assert_ptr_ne(out_claims, NULL);

	oauth2_json_string_get(_log, out_claims, "sub", &value, NULL);
	ck_assert_ptr_ne(value, NULL);
	ck_assert_str_eq(value, "joe");
	oauth2_mem_free(value);

	json_decref(in_claims);
	json_decref(out_claims);
}
END_TEST

START_TEST(test_apache_authz_match_claim)
{
	json_error_t err;
	oauth2_apache_request_ctx_t *ctx = NULL;
	const char *s_claims = "{ \"sub\": \"joe\" }";
	json_t *claims = NULL;
	bool rc = false;

	ctx = oauth2_apache_request_context(request, check_apache_log_request,
					    "check_apache");
	claims = json_loads(s_claims, 0, &err);

	rc = oauth2_apache_authz_match_claim(ctx, "sub:joe", claims);
	ck_assert_int_eq(rc, true);

	rc = oauth2_apache_authz_match_claim(ctx, "sub:hans", claims);
	ck_assert_int_eq(rc, false);

	json_decref(claims);
}
END_TEST

START_TEST(test_apache_authz_match_claim_expr)
{
	json_error_t err;
	oauth2_apache_request_ctx_t *ctx = NULL;
	const char *s_claims = "{ \"scope\": \"one, two, three, four, five\", "
			       "\"scopes\": [ \"one\", \"two\", \"three\" ] }";
	json_t *claims = NULL;
	bool rc = false;

	ctx = oauth2_apache_request_context(request, check_apache_log_request,
					    "check_apache");
	claims = json_loads(s_claims, 0, &err);

	rc = oauth2_apache_authz_match_claim(ctx, "scope~(^|\\s)(one)($|\\s|,)",
					     claims);
	ck_assert_int_eq(rc, true);

	rc = oauth2_apache_authz_match_claim(
	    ctx, "scope~(^|\\s)(four)($|\\s|,)", claims);
	ck_assert_int_eq(rc, true);

	rc = oauth2_apache_authz_match_claim(
	    ctx, "scope~(^|\\s)(five)($|\\s|,)", claims);
	ck_assert_int_eq(rc, true);

	rc = oauth2_apache_authz_match_claim(ctx, "scope~(^|\\s)(six)($|\\s|,)",
					     claims);
	ck_assert_int_eq(rc, false);

	rc = oauth2_apache_authz_match_claim(ctx, "scopes~^three$", claims);
	ck_assert_int_eq(rc, true);

	rc = oauth2_apache_authz_match_claim(ctx, "scopes~^four", claims);
	ck_assert_int_eq(rc, false);

	json_decref(claims);
}
END_TEST

START_TEST(test_apache_authorize)
{
	json_error_t err;
	oauth2_apache_request_ctx_t *ctx = NULL;
	const char *s_claims = "{ \"sub\": \"joe\" }";
	json_t *claims = NULL;
	authz_status rc = AUTHZ_DENIED;

	ctx = oauth2_apache_request_context(request, check_apache_log_request,
					    "check_apache");
	claims = json_loads(s_claims, 0, &err);

	rc = oauth2_apache_authorize(ctx, claims, "sub:hans",
				     oauth2_apache_authz_match_claim);
	ck_assert_int_eq(rc, AUTHZ_DENIED_NO_USER);

	request->user = "joe";
	rc = oauth2_apache_authorize(ctx, claims, "sub:hans",
				     oauth2_apache_authz_match_claim);
	ck_assert_int_eq(rc, AUTHZ_DENIED);

	rc = oauth2_apache_authorize(ctx, claims, "sub:joe",
				     oauth2_apache_authz_match_claim);
	ck_assert_int_eq(rc, AUTHZ_GRANTED);

	json_decref(claims);
}
END_TEST

START_TEST(test_apache_http_response_set)
{
	bool rc = false;
	oauth2_http_response_t *response = NULL;

	response = oauth2_http_response_init(_log);

	rc = oauth2_apache_http_response_set(_log, response, request);
	ck_assert_int_eq(rc, true);

	oauth2_http_response_free(_log, response);
}
END_TEST

Suite *oauth2_check_apache_suite()
{
	Suite *s = suite_create("apache");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_apache_request_state);
	tcase_add_test(c, test_apache_authz_match_claim);
	tcase_add_test(c, test_apache_authz_match_claim_expr);
	tcase_add_test(c, test_apache_authorize);
	tcase_add_test(c, test_apache_http_response_set);

	suite_add_tcase(s, c);

	return s;
}
