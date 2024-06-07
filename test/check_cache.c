/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV - www.zmartzone.eu
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "check_liboauth2.h"
#include "oauth2/cache.h"
#include "oauth2/cfg.h"
#include "oauth2/mem.h"
#include <check.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static oauth2_log_t *_log = 0;

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(_log);
}

// oauth2_cfg_set_cache

START_TEST(test_cache_bogus)
{
	char *rv = 0;
	rv = oauth2_cfg_set_cache(_log, 0, "bogus", 0);
	ck_assert_ptr_ne(rv, 0);
	oauth2_mem_free(rv);
}
END_TEST

static void _test_basic_cache(oauth2_cache_t *c)
{
	bool rc = false;
	char *value = 0;

	rc = oauth2_cache_set(_log, c, "piet", "klaas", 2);
	ck_assert_int_eq(rc, true);

	value = 0;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, 0);
	ck_assert_str_eq(value, "klaas");
	oauth2_mem_free(value);

	sleep(3);

	value = 0;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, 0);

	rc = oauth2_cache_set(_log, c, "piet", "klaas", 1);
	ck_assert_int_eq(rc, true);

	value = 0;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, 0);
	ck_assert_str_eq(value, "klaas");
	oauth2_mem_free(value);

	rc = oauth2_cache_set(_log, c, "piet", 0, 0);
	ck_assert_int_eq(rc, true);

	value = 0;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, 0);

	value = 0;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, 0);
}

START_TEST(test_cache_shm)
{
	bool rc = false;
	char *value = 0;
	oauth2_cache_t *c = 0;
	char *rv = 0;

	rv = oauth2_cfg_set_cache(_log, 0, "shm",
				  "max_val_size=16&max_entries=2");
	ck_assert_ptr_eq(rv, 0);
	c = oauth2_cache_obtain(_log, 0);
	ck_assert_ptr_ne(c, 0);

	_test_basic_cache(c);

	// override the max nr of entries
	rc = oauth2_cache_set(_log, c, "hans", "zandbelt", 1);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(_log, c, "nog", "een", 1);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(_log, c, "hallo", "dan", 1);
	ck_assert_int_eq(rc, true);

	value = 0;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, 0);

	rc = oauth2_cache_set(_log, c, "value_too_long", "12345678901234567890",
			      1);
	ck_assert_int_eq(rc, false);

	rv = oauth2_cfg_set_cache(
	    _log, 0, "shm",
	    "name=short_key_size&key_hash_algo=none&max_key_size=8");
	ck_assert_ptr_eq(rv, 0);
	c = oauth2_cache_obtain(_log, "short_key_size");
	ck_assert_ptr_ne(c, 0);

	rc = oauth2_cache_set(_log, c, "hans", "zandbelt", 1);
	ck_assert_int_eq(rc, true);

	rc = oauth2_cache_set(_log, c,
			      "key_too_long_"
			      "123456789012345678901234567890123456789012345678"
			      "9012345678901234567890",
			      "12345678901234567890", 1);
	ck_assert_int_eq(rc, false);
}
END_TEST

START_TEST(test_cache_file)
{
	bool rc = false;
	oauth2_cache_t *c = 0;
	char *rv = 0;
	char *value = 0;

	rv = oauth2_cfg_set_cache(
	    _log, 0, "file",
	    "name=file&key_hash_algo=none&max_key_size=8&clean_interval=1");
	ck_assert_ptr_eq(rv, 0);
	c = oauth2_cache_obtain(_log, "file");
	ck_assert_ptr_ne(c, 0);

	_test_basic_cache(c);

	rc = oauth2_cache_set(_log, c, "hans", "zandbelt", 1);
	ck_assert_int_eq(rc, true);

	// also wait for the cache clean cycle (interval=1) to run
	sleep(1);

	rc = oauth2_cache_set(_log, c, "hans2", "zandbelt2", 1);
	ck_assert_int_eq(rc, true);

	value = 0;
	rc = oauth2_cache_get(_log, c, "hans", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, 0);

	// TODO: test file /tmp/mod-auth-openidc-hans exists?
}
END_TEST

#ifdef HAVE_LIBMEMCACHE
START_TEST(test_cache_memcache)
{
	oauth2_cache_t *c = 0;
	char *rv = 0;

	rv = oauth2_cfg_set_cache(_log, 0, "memcache", "name=memcache");
	ck_assert_ptr_eq(rv, 0);
	c = oauth2_cache_obtain(_log, "memcache");
	ck_assert_ptr_ne(c, 0);

	_test_basic_cache(c);
}
END_TEST
#endif

#ifdef HAVE_LIBHIREDIS
START_TEST(test_cache_redis)
{
	oauth2_cache_t *c = 0;
	char *rv = 0;

	//&password=foobared
	rv = oauth2_cfg_set_cache(_log, 0, "redis",
				  "name=redis");
	ck_assert_ptr_eq(rv, 0);
	c = oauth2_cache_obtain(_log, "redis");
	ck_assert_ptr_ne(c, 0);

	_test_basic_cache(c);
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

	tcase_set_timeout(c, 8);

	suite_add_tcase(s, c);

	return s;
}
