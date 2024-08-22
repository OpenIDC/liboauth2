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
#include "oauth2/util.h"
#include <check.h>
#include <curl/curl.h>
#include <stdlib.h>

static oauth2_mem_alloc_fn_t _save_alloc = NULL;
static oauth2_mem_realloc_fn_t _save_realloc = NULL;
static oauth2_mem_dealloc_fn_t _save_dealloc = NULL;

static void *test_alloc(size_t amt)
{
	return malloc(amt);
}

static void *test_realloc(void *ptr, size_t amt)
{
	return realloc(ptr, amt);
}

static void test_dealloc(void *ptr)
{
	free(ptr);
}

static void test_mem_functions_set()
{
	_save_alloc = oauth2_mem_get_alloc();
	_save_realloc = oauth2_mem_get_realloc();
	_save_dealloc = oauth2_mem_get_dealloc();

	oauth2_mem_set_alloc_funcs(test_alloc, test_realloc, test_dealloc);
}

static void test_mem_functions_reset()
{
	oauth2_mem_set_alloc_funcs(_save_alloc, _save_realloc, _save_dealloc);
	_save_alloc = NULL;
	_save_realloc = NULL;
	_save_dealloc = NULL;
}

static void *test_alloc3(size_t amt, const char *file, int line)
{
	return malloc(amt);
}

static void *test_realloc3(void *ptr, size_t amt, const char *file, int line)
{
	return realloc(ptr, amt);
}

static void test_dealloc3(void *ptr, const char *file, int line)
{
	free(ptr);
}

static oauth2_mem_alloc3_fn_t _save_alloc3 = NULL;
static oauth2_mem_realloc3_fn_t _save_realloc3 = NULL;
static oauth2_mem_dealloc3_fn_t _save_dealloc3 = NULL;

static void test_mem_functions_set3()
{
	_save_alloc3 = oauth2_mem_get_alloc3();
	_save_realloc3 = oauth2_mem_get_realloc3();
	_save_dealloc3 = oauth2_mem_get_dealloc3();

	oauth2_mem_set_alloc_ex_funcs(test_alloc3, test_realloc3,
				      test_dealloc3);
}

/*
 * TODO: why does this result in a timeout?
 *       probably we can call this only once anyhow, but would it affect the
other check_util tests?
 *       perhaps separate it out in a different suite then?
static void test_mem_functions_reset3() {
	cjose_set_alloc_ex_funcs(_save_alloc3, _save_realloc3, _save_dealloc3);
	oauth2_mem_set_alloc_ex_funcs(_save_alloc3, _save_realloc3,
_save_dealloc3);
	_save_alloc3 = NULL;
	_save_realloc3 = NULL;
	_save_dealloc3 = NULL;
}
*/

static oauth2_log_t *_log = 0;

static void setup(void)
{
	// provide coverage for oauth2_mem_calloc_callback
	// NB: the setup for cURL can only be initialized once and stays this
	// way
	test_mem_functions_set();

	CURL *curl1 = NULL, *curl2 = NULL;
	curl1 = curl_easy_init();
	curl2 = curl_easy_duphandle(curl1);
	curl_easy_cleanup(curl2);
	curl_easy_cleanup(curl1);

	// for coverage
	oauth2_log_free(NULL);

	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(_log);
}

START_TEST(test_log)
{
	// mostly to complete coverage

	// TODO: could return bytes written from oauth2_log statements
	oauth2_debug(NULL, NULL);
	// TOOD: could return bool from oauth2_log_sink_add
	oauth2_log_sink_add(_log, &oauth2_log_sink_stderr);
	oauth2_info(_log, NULL);
	oauth2_info(_log, "");
	oauth2_log_sink_level_set(&oauth2_log_sink_stderr, OAUTH2_LOG_ERROR);
}
END_TEST

START_TEST(test_mem)
{
	void *ptr = NULL;

	ck_assert(NULL != oauth2_mem_get_alloc());
	ck_assert(NULL != oauth2_mem_get_realloc());
	ck_assert(NULL != oauth2_mem_get_dealloc());
	ck_assert(NULL != oauth2_mem_get_alloc3());
	ck_assert(NULL != oauth2_mem_get_realloc3());
	ck_assert(NULL != oauth2_mem_get_dealloc3());

	test_mem_functions_set();

	ck_assert(NULL != oauth2_mem_get_alloc());
	ck_assert(NULL != oauth2_mem_get_realloc());
	ck_assert(NULL != oauth2_mem_get_dealloc());
	ck_assert(NULL != oauth2_mem_get_alloc3());
	ck_assert(NULL != oauth2_mem_get_realloc3());
	ck_assert(NULL != oauth2_mem_get_dealloc3());

	ptr = oauth2_mem_alloc(8);
	ptr = oauth2_mem_get_realloc()(ptr, 8);
	oauth2_mem_free(ptr);

	test_mem_functions_reset();

	ck_assert(NULL != oauth2_mem_get_alloc());
	ck_assert(NULL != oauth2_mem_get_realloc());
	ck_assert(NULL != oauth2_mem_get_dealloc());
	ck_assert(NULL != oauth2_mem_get_alloc3());
	ck_assert(NULL != oauth2_mem_get_realloc3());
	ck_assert(NULL != oauth2_mem_get_dealloc3());

	test_mem_functions_set3();

	ck_assert(NULL != oauth2_mem_get_alloc());
	ck_assert(NULL != oauth2_mem_get_realloc());
	ck_assert(NULL != oauth2_mem_get_dealloc());
	ck_assert(NULL != oauth2_mem_get_alloc3());
	ck_assert(NULL != oauth2_mem_get_realloc3());
	ck_assert(NULL != oauth2_mem_get_dealloc3());

	ptr = oauth2_mem_alloc(8);
	ptr = oauth2_mem_get_realloc()(ptr, 8);
	oauth2_mem_free(ptr);

	// test_mem_functions_reset3();
}
END_TEST

START_TEST(test_strdup)
{
	char *src = NULL, *dst = NULL;

	src = "bla";
	dst = NULL;
	dst = oauth2_strdup(src);
	ck_assert_ptr_ne(dst, NULL);
	ck_assert_str_eq(src, dst);
	oauth2_mem_free(dst);

	src = NULL;
	dst = NULL;
	dst = oauth2_strdup(src);
	ck_assert_ptr_eq(dst, NULL);
	oauth2_mem_free(dst);
}
END_TEST

START_TEST(test_base64url_encode)
{
	size_t dst_len;
	char *dst;

	const char *plain = "Node.js is awesome.";
	const char *encoded = "Tm9kZS5qcyBpcyBhd2Vzb21lLg";

	dst_len = oauth2_base64url_encode(_log, (const uint8_t *)plain,
					  strlen(plain), &dst);

	ck_assert_int_eq(dst_len, strlen(encoded));
	ck_assert_str_eq(dst, encoded);

	oauth2_mem_free(dst);

	dst = NULL;
	dst_len = oauth2_base64url_encode(_log, NULL, 0, &dst);
	ck_assert_ptr_eq(dst, NULL);
	ck_assert_int_eq(dst_len, 0);

	dst_len = oauth2_base64url_encode(_log, NULL, 0, NULL);
	ck_assert_int_eq(dst_len, 0);

	dst_len = oauth2_base64url_encode(_log, (const uint8_t *)"", 0, NULL);
	ck_assert_int_eq(dst_len, 0);
}
END_TEST

START_TEST(test_base64url_decode)
{
	uint8_t *dst;
	size_t dst_len;
	bool rc;

	const char *encoded = "Tm9kZS5qcyBpcyBhd2Vzb21lLg";
	const char *plain = "Node.js is awesome.";

	rc = oauth2_base64url_decode(_log, encoded, &dst, &dst_len);

	ck_assert_int_eq(rc, true);
	ck_assert_int_eq(dst_len, strlen(plain));
	ck_assert(strncmp((const char *)dst, plain, dst_len) == 0);

	oauth2_mem_free(dst);

	dst = NULL;
	dst_len = 0;
	rc = oauth2_base64url_decode(_log, NULL, &dst, &dst_len);

	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(dst, NULL);
	ck_assert_int_eq(dst_len, 0);

	rc = oauth2_base64url_decode(_log, NULL, NULL, 0);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(dst, NULL);
	ck_assert_int_eq(dst_len, 0);

	rc = oauth2_base64url_decode(_log, "", NULL, 0);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(dst, NULL);
	ck_assert_int_eq(dst_len, 0);
}
END_TEST

START_TEST(test_url_encode)
{
	char *src = NULL, *dst = NULL, *enc = NULL;

	src = "bla bla";
	enc = "bla%20bla";
	dst = oauth2_url_encode(_log, src);
	ck_assert_str_eq(dst, enc);
	oauth2_mem_free(dst);

	src = "Hello Günter";
	enc = "Hello%20G%C3%BCnter";
	dst = oauth2_url_encode(_log, src);
	ck_assert_str_eq(dst, enc);
	oauth2_mem_free(dst);

	dst = NULL;
	src = NULL;
	dst = oauth2_url_encode(_log, src);
	ck_assert_ptr_eq(dst, NULL);
}
END_TEST

START_TEST(test_url_decode)
{
	char *dst = NULL, *src = NULL, *dec = NULL;

	src = "bla%20bla";
	dec = "bla bla";
	dst = oauth2_url_decode(_log, src);
	ck_assert_str_eq(dst, dec);
	oauth2_mem_free(dst);

	dst = NULL;
	src = "http://www.example.com/path/foo+bar/path?query+name=query+value";
	dec = "http://www.example.com/path/foo bar/path?query name=query value";
	dst = oauth2_url_decode(_log, src);
	ck_assert_str_eq(dst, dec);
	oauth2_mem_free(dst);

	src = "Hello%20G%C3%BCnter";
	dec = "Hello Günter";
	dst = oauth2_url_decode(_log, src);
	ck_assert_str_eq(dst, dec);
	oauth2_mem_free(dst);

	dst = NULL;
	src = NULL;
	dst = oauth2_url_decode(_log, src);
	ck_assert_ptr_eq(dst, NULL);
}
END_TEST

START_TEST(test_html_encode)
{
	char *src = NULL, *dst = NULL, *enc = NULL;

	src = "bla&bla";
	enc = "bla&amp;bla";
	dst = oauth2_html_escape(_log, src);
	ck_assert_str_eq(dst, enc);
	oauth2_mem_free(dst);
	dst = NULL;

	// https://www.w3schools.com/php/func_string_htmlentities.asp
	src = "<a href=\"https://www.w3schools.com\">Go to w3schools.com</a>";
	enc = "&lt;a href=&quot;https://www.w3schools.com&quot;&gt;Go to "
	      "w3schools.com&lt;/a&gt;";
	dst = oauth2_html_escape(_log, src);
	ck_assert_str_eq(dst, enc);
	oauth2_mem_free(dst);
	dst = NULL;

	src = NULL;
	dst = oauth2_html_escape(_log, src);
	ck_assert_ptr_eq(dst, NULL);
}
END_TEST

START_TEST(test_random)
{
	char *rv = NULL;

	rv = oauth2_rand_str(_log, 8);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_str_ne(rv, "");
	ck_assert_int_eq(strlen(rv), 8);
	oauth2_mem_free(rv);

	rv = oauth2_rand_str(_log, 16);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_str_ne(rv, "");
	ck_assert_int_eq(strlen(rv), 16);
	oauth2_mem_free(rv);

	rv = oauth2_rand_str(_log, 7);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_str_ne(rv, "");
	ck_assert_int_eq(strlen(rv), 7);
	oauth2_mem_free(rv);
}
END_TEST

Suite *oauth2_check_util_suite()
{
	Suite *s = suite_create("util");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_log);
	tcase_add_test(c, test_mem);
	tcase_add_test(c, test_strdup);
	tcase_add_test(c, test_base64url_encode);
	tcase_add_test(c, test_base64url_decode);
	tcase_add_test(c, test_url_encode);
	tcase_add_test(c, test_url_decode);
	tcase_add_test(c, test_html_encode);
	tcase_add_test(c, test_random);

	suite_add_tcase(s, c);

	return s;
}
