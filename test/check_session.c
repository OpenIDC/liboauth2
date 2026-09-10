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
#include "oauth2/cfg.h"
#include "oauth2/mem.h"
#include "oauth2/session.h"
#include "oauth2/util.h"
#include <check.h>
#include <string.h>

static oauth2_log_t *_log = 0;

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
	oauth2_crypto_passphrase_set(_log, NULL,
				     "check_session_passphrase_0123456789");
}

static void teardown(void)
{
	// the session configurations created below are registered globally
	// and released here
	oauth2_shutdown(_log);
}

/*
 * a "cookie" type configuration; registered globally, do not free
 */
static oauth2_cfg_session_t *_session_cfg(const char *name, const char *options)
{
	oauth2_cfg_session_t *cfg = oauth2_cfg_session_init(_log);
	char *opts = oauth2_stradd(NULL, "name=", name, options);
	char *rv = oauth2_cfg_session_set_options(_log, cfg, "cookie", opts);
	ck_assert_ptr_eq(rv, NULL);
	oauth2_mem_free(opts);
	return cfg;
}

/*
 * the "name=value" part of the Set-Cookie header a save produced
 */
static char *_session_cookie(oauth2_http_response_t *response, const char *name)
{
	char *prefix = oauth2_stradd(NULL, name, "=", NULL);
	const char *hdr = oauth2_http_response_header_set_cookie_prefix_get(
	    _log, response, prefix);
	const char *end = NULL;
	char *cookie = NULL;
	ck_assert_ptr_ne(hdr, NULL);
	end = strchr(hdr, ';');
	cookie = end ? oauth2_strndup(hdr, end - hdr) : oauth2_strdup(hdr);
	oauth2_mem_free(prefix);
	return cookie;
}

/*
 * save the record on a fresh response and load it back from a fresh request
 * carrying the resulting cookie
 */
static oauth2_session_rec_t *_session_save_load(oauth2_cfg_session_t *cfg,
						oauth2_session_rec_t *rec)
{
	bool rc = false;
	char *cookie = NULL;
	oauth2_http_request_t *request = oauth2_http_request_init(_log);
	oauth2_http_response_t *response = oauth2_http_response_init(_log);
	oauth2_session_rec_t *loaded = NULL;

	rc = oauth2_session_save(_log, cfg, request, response, rec);
	ck_assert_int_eq(rc, true);

	cookie = _session_cookie(response,
				 oauth2_cfg_session_cookie_name_get(_log, cfg));
	oauth2_http_request_free(_log, request);
	oauth2_http_response_free(_log, response);

	request = oauth2_http_request_init(_log);
	oauth2_http_request_header_set(_log, request, "Cookie", cookie);
	rc = oauth2_session_load(_log, cfg, request, &loaded);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(loaded, NULL);

	oauth2_http_request_free(_log, request);
	oauth2_mem_free(cookie);

	return loaded;
}

START_TEST(test_session_rec)
{
	oauth2_session_rec_t *rec = NULL;
	json_t *c1 = json_pack("{s:s}", "sub", "one");
	json_t *c2 = json_pack("{s:s}", "sub", "two");

	// NULL guard
	oauth2_session_rec_free(_log, NULL);

	rec = oauth2_session_rec_init(_log);
	ck_assert_ptr_ne(rec, NULL);
	ck_assert_uint_eq(oauth2_session_rec_expiry_get(_log, rec), 0);

	// setting claims twice replaces them, releasing the first reference
	ck_assert_int_eq(oauth2_session_rec_id_token_claims_set(_log, rec, c1),
			 true);
	ck_assert_int_eq(oauth2_session_rec_id_token_claims_set(_log, rec, c2),
			 true);
	ck_assert_ptr_eq(oauth2_session_rec_id_token_claims_get(_log, rec), c2);
	ck_assert_uint_eq(c1->refcount, 1);
	ck_assert_uint_eq(c2->refcount, 2);

	// NULL leaves the claims alone
	ck_assert_int_eq(
	    oauth2_session_rec_userinfo_claims_set(_log, rec, NULL), true);
	ck_assert_ptr_eq(oauth2_session_rec_userinfo_claims_get(_log, rec),
			 NULL);

	oauth2_session_rec_free(_log, rec);
	ck_assert_uint_eq(c2->refcount, 1);

	json_decref(c1);
	json_decref(c2);
}
END_TEST

START_TEST(test_session_cfg)
{
	oauth2_cfg_session_t *cfg = NULL;
	char *rv = NULL;

	ck_assert_ptr_eq(oauth2_cfg_session_cache_get(_log, NULL), NULL);

	cfg = _session_cfg("cfg", "&cookie.name=first&cookie.path=/a");
	ck_assert_str_eq(oauth2_cfg_session_cookie_name_get(_log, cfg),
			 "first");
	ck_assert_str_eq(oauth2_cfg_session_cookie_path_get(_log, cfg), "/a");

	// repeating the options replaces the earlier values
	rv = oauth2_cfg_session_set_options(
	    _log, cfg, "cookie", "cookie.name=second&cookie.path=/b");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_str_eq(oauth2_cfg_session_cookie_name_get(_log, cfg),
			 "second");
	ck_assert_str_eq(oauth2_cfg_session_cookie_path_get(_log, cfg), "/b");
}
END_TEST

START_TEST(test_session_roundtrip_and_handle)
{
	bool rc = false;
	oauth2_cfg_session_t *cfg = NULL;
	oauth2_session_rec_t *rec = NULL, *loaded = NULL;
	oauth2_http_request_t *request = NULL;
	oauth2_http_response_t *response = NULL;
	oauth2_time_t now = 0, expiry = 0;

	cfg = _session_cfg("rt", "&cookie.name=rt&inactivity_timeout=60&"
				 "max_duration=3600");

	rec = oauth2_session_rec_init(_log);
	oauth2_session_rec_user_set(_log, rec, "joe");

	// the first save sets the expiry to now + inactivity timeout
	now = oauth2_time_now_sec();
	loaded = _session_save_load(cfg, rec);
	expiry = oauth2_session_rec_expiry_get(_log, rec);
	ck_assert_uint_ge(expiry, now + 60);
	ck_assert_uint_le(expiry, now + 61);

	ck_assert_str_eq(oauth2_session_rec_user_get(_log, loaded), "joe");
	ck_assert_uint_eq(oauth2_session_rec_expiry_get(_log, loaded), expiry);

	// with the inactivity timeout mostly used up, handling a request
	// slides the expiry forward and saves the session again
	request = oauth2_http_request_init(_log);
	response = oauth2_http_response_init(_log);
	oauth2_session_rec_expiry_set(_log, loaded, now + 10);
	rc = oauth2_session_handle(_log, cfg, request, response, loaded);
	ck_assert_int_eq(rc, true);
	ck_assert_uint_ge(oauth2_session_rec_expiry_get(_log, loaded),
			  now + 60);
	ck_assert_ptr_ne(oauth2_http_response_header_set_cookie_prefix_get(
			     _log, response, "rt="),
			 NULL);
	oauth2_http_response_free(_log, response);

	// a recently saved session is left alone
	response = oauth2_http_response_init(_log);
	oauth2_session_rec_expiry_set(_log, loaded, now + 58);
	rc = oauth2_session_handle(_log, cfg, request, response, loaded);
	ck_assert_int_eq(rc, true);
	ck_assert_uint_eq(oauth2_session_rec_expiry_get(_log, loaded),
			  now + 58);
	ck_assert_ptr_eq(oauth2_http_response_header_set_cookie_prefix_get(
			     _log, response, "rt="),
			 NULL);
	oauth2_http_response_free(_log, response);
	oauth2_http_request_free(_log, request);

	oauth2_session_rec_free(_log, loaded);
	oauth2_session_rec_free(_log, rec);
}
END_TEST

START_TEST(test_session_expired)
{
	oauth2_cfg_session_t *cfg = NULL;
	oauth2_session_rec_t *rec = NULL, *loaded = NULL;
	oauth2_time_t now = oauth2_time_now_sec();

	cfg = _session_cfg("exp", "&cookie.name=exp&inactivity_timeout=60&"
				  "max_duration=3600");

	// a session past its expiry loads as a new, empty one
	rec = oauth2_session_rec_init(_log);
	oauth2_session_rec_user_set(_log, rec, "joe");
	oauth2_session_rec_expiry_set(_log, rec, now - 1);
	loaded = _session_save_load(cfg, rec);
	ck_assert_ptr_eq(oauth2_session_rec_user_get(_log, loaded), NULL);
	ck_assert_uint_eq(oauth2_session_rec_expiry_get(_log, loaded), 0);
	oauth2_session_rec_free(_log, loaded);
	oauth2_session_rec_free(_log, rec);

	// so does one that exceeded the maximum duration
	rec = oauth2_session_rec_init(_log);
	oauth2_session_rec_user_set(_log, rec, "joe");
	oauth2_session_rec_start_set(_log, rec, now - 4000);
	loaded = _session_save_load(cfg, rec);
	ck_assert_ptr_eq(oauth2_session_rec_user_get(_log, loaded), NULL);
	ck_assert_uint_eq(oauth2_session_rec_expiry_get(_log, loaded), 0);
	ck_assert_uint_ge(oauth2_session_rec_start_get(_log, loaded), now);
	oauth2_session_rec_free(_log, loaded);
	oauth2_session_rec_free(_log, rec);
}
END_TEST

Suite *oauth2_check_session_suite()
{
	Suite *s = suite_create("session");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_session_rec);
	tcase_add_test(c, test_session_cfg);
	tcase_add_test(c, test_session_roundtrip_and_handle);
	tcase_add_test(c, test_session_expired);

	suite_add_tcase(s, c);

	return s;
}
