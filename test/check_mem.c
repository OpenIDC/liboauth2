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
}

static void teardown(void)
{
}

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
}
END_TEST

Suite *oauth2_check_mem_suite()
{
	Suite *s = suite_create("mem");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_mem);

	suite_add_tcase(s, c);

	return s;
}
