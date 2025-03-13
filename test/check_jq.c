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
#include "oauth2/jq.h"
#include "oauth2/mem.h"
#include <check.h>

static oauth2_log_t *_log = 0;

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(_log);
}

START_TEST(test_jq_compile)
{
	bool rc = false;

	rc = oauth2_jq_filter_compile(_log, ".add + 1", NULL);
	ck_assert_int_eq(rc, true);

	rc = oauth2_jq_filter_compile(_log, "bla", NULL);
	ck_assert_int_eq(rc, false);
}

START_TEST(test_jq_filter)
{
	bool rc = false;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;
	char *result = NULL;

	rv = oauth2_cfg_set_cache(_log, NULL, "shm", NULL);
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, NULL);
	ck_assert_ptr_ne(c, NULL);

	rc = oauth2_jq_filter(_log, c, "{\"add\":1}", ".add + 1", &result);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(result, "2");
	oauth2_mem_free(result);

	rc = oauth2_jq_filter(_log, c, "{\"add\":2}", ".add + 1", &result);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(result, "3");
	oauth2_mem_free(result);

	// should use cache
	rc = oauth2_jq_filter(_log, c, "{\"add\":2}", ".add + 1", &result);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(result, "3");
	oauth2_mem_free(result);
}
END_TEST

Suite *oauth2_check_jq_suite()
{
	Suite *s = suite_create("jq");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_jq_compile);
	tcase_add_test(c, test_jq_filter);

	suite_add_tcase(s, c);

	return s;
}
