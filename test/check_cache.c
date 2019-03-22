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

#include "oauth2/cache.h"
#include "oauth2/mem.h"
#include <check.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static oauth2_log_t *log = 0;

static void setup(void)
{
	log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(log);
}

START_TEST(test_cache_bogus)
{
	oauth2_cache_t *c = NULL;
	c = oauth2_cache_init(log, "bogus", NULL);
	ck_assert_ptr_eq(c, NULL);
}
END_TEST

static void _test_basic_cache(oauth2_cache_t *c)
{
	bool rc = false;
	char *value = NULL;

	rc = oauth2_cache_set(log, c, "piet", "klaas", 1);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, NULL);
	ck_assert_str_eq(value, "klaas");
	oauth2_mem_free(value);

	sleep(1);

	value = NULL;
	rc = oauth2_cache_get(log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_cache_set(log, c, "piet", "klaas", 1);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, NULL);
	ck_assert_str_eq(value, "klaas");
	oauth2_mem_free(value);

	rc = oauth2_cache_set(log, c, "piet", NULL, 0);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);

	value = NULL;
	rc = oauth2_cache_get(log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);
}

START_TEST(test_cache_shm)
{
	bool rc = false;
	char *value = NULL;
	oauth2_cache_t *c = NULL;

	c = oauth2_cache_init(log, "shm", "max_val_size=16&max_entries=2");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_post_config(log, c);
	ck_assert_int_eq(rc, true);

	_test_basic_cache(c);

	// override the max nr of entries
	rc = oauth2_cache_set(log, c, "hans", "zandbelt", 1);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(log, c, "nog", "een", 1);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(log, c, "hallo", "dan", 1);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_cache_set(log, c, "value_too_long", "12345678901234567890",
			      1);
	ck_assert_int_eq(rc, false);

	oauth2_cache_free(log, c);

	c = oauth2_cache_init(log, NULL, "key_hash_algo=none&max_key_size=8");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_post_config(log, c);
	ck_assert_int_eq(rc, true);

	rc = oauth2_cache_set(log, c, "hans", "zandbelt", 1);
	ck_assert_int_eq(rc, true);

	rc =
	    oauth2_cache_set(log, c, "key_too_long", "12345678901234567890", 1);
	ck_assert_int_eq(rc, false);

	oauth2_cache_free(log, c);
}
END_TEST

START_TEST(test_cache_file)
{
	bool rc = false;
	oauth2_cache_t *c = NULL;

	c = oauth2_cache_init(log, "file", "key_hash_algo=none");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_post_config(log, c);
	ck_assert_int_eq(rc, true);

	_test_basic_cache(c);

	rc = oauth2_cache_set(log, c, "hans", "zandbelt", 10);
	ck_assert_int_eq(rc, true);
	// TODO: test file /tmp/mod-auth-openidc-hans exists?

	oauth2_cache_free(log, c);
}
END_TEST

#ifdef HAVE_LIBMEMCACHE
START_TEST(test_cache_memcache)
{
	bool rc = false;
	oauth2_cache_t *c = NULL;

	c = oauth2_cache_init(log, "memcache", NULL);
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_post_config(log, c);
	ck_assert_int_eq(rc, true);

	_test_basic_cache(c);

	oauth2_cache_free(log, c);
}
END_TEST
#endif

#ifdef HAVE_LIBHIREDIS
START_TEST(test_cache_redis)
{
	bool rc = false;
	oauth2_cache_t *c = NULL;

	c = oauth2_cache_init(log, "redis", NULL);
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_post_config(log, c);
	ck_assert_int_eq(rc, true);

	_test_basic_cache(c);

	oauth2_cache_free(log, c);
}
END_TEST
#endif

Suite *oauth2_check_cache_suite()
{
	Suite *s = suite_create("cache");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_cache_bogus);
	tcase_add_test(c, test_cache_shm);
	tcase_add_test(c, test_cache_file);
#ifdef HAVE_LIBMEMCACHE
	tcase_add_test(c, test_cache_memcache);
#endif
#ifdef HAVE_LIBHIREDIS
	tcase_add_test(c, test_cache_redis);
#endif
	suite_add_tcase(s, c);

	return s;
}
