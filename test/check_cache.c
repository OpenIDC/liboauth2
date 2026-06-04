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
#include "oauth2/cache.h"
#include "oauth2/cfg.h"
#include "oauth2/mem.h"
#include <check.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static oauth2_log_t *_log = 0;

// defined in src/cache.c, linked via liboauth2.la, not (yet) in a public header
bool oauth2_cache_child_init(oauth2_log_t *log, oauth2_cache_t *cache);

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
	char *rv = NULL;
	rv = oauth2_cfg_set_cache(_log, NULL, "bogus", NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
}
END_TEST

static void _test_basic_cache(oauth2_cache_t *c)
{
	bool rc = false;
	char *value = NULL;

	rc = oauth2_cache_set(_log, c, "piet", "klaas", 1);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, NULL);
	ck_assert_str_eq(value, "klaas");
	oauth2_mem_free(value);

	// ttl=1 + sleep(2) keeps a 1s margin past expiry (1s clock granularity)
	sleep(2);

	value = NULL;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_cache_set(_log, c, "piet", "klaas", 1);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, NULL);
	ck_assert_str_eq(value, "klaas");
	oauth2_mem_free(value);

	rc = oauth2_cache_set(_log, c, "piet", NULL, 0);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);

	value = NULL;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);
}

START_TEST(test_cache_shm)
{
	bool rc = false;
	char *value = NULL;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	rv = oauth2_cfg_set_cache(_log, NULL, "shm",
				  "max_val_size=16&max_entries=2");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, NULL);
	ck_assert_ptr_ne(c, NULL);

	_test_basic_cache(c);

	// override the max nr of entries
	rc = oauth2_cache_set(_log, c, "hans", "zandbelt", 1);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(_log, c, "nog", "een", 1);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(_log, c, "hallo", "dan", 1);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(_log, c, "piet", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_cache_set(_log, c, "value_too_long", "12345678901234567890",
			      1);
	ck_assert_int_eq(rc, false);

	rv = oauth2_cfg_set_cache(
	    _log, NULL, "shm",
	    "name=short_key_size&key_hash_algo=none&max_key_size=8");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "short_key_size");
	ck_assert_ptr_ne(c, NULL);

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
	oauth2_cache_t *c = NULL;
	char *rv = NULL;
	char *value = NULL;

	rv = oauth2_cfg_set_cache(
	    _log, NULL, "file",
	    "name=file&key_hash_algo=none&max_key_size=8&clean_interval=1");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "file");
	ck_assert_ptr_ne(c, NULL);

	_test_basic_cache(c);

	rc = oauth2_cache_set(_log, c, "hans", "zandbelt", 1);
	ck_assert_int_eq(rc, true);

	// also wait for the cache clean cycle (interval=1) to run
	sleep(1);

	rc = oauth2_cache_set(_log, c, "hans2", "zandbelt2", 1);
	ck_assert_int_eq(rc, true);

	value = NULL;
	rc = oauth2_cache_get(_log, c, "hans", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_eq(value, NULL);

	// TODO: test file /tmp/mod-auth-openidc-hans exists?
}
END_TEST

#ifdef HAVE_LIBMEMCACHE
START_TEST(test_cache_memcache)
{
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	rv = oauth2_cfg_set_cache(_log, NULL, "memcache", "name=memcache");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "memcache");
	ck_assert_ptr_ne(c, NULL);

	_test_basic_cache(c);
}
END_TEST
#endif

#ifdef HAVE_LIBHIREDIS
START_TEST(test_cache_redis)
{
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	//&password=foobared
	rv = oauth2_cfg_set_cache(_log, NULL, "redis", "name=redis");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "redis");
	ck_assert_ptr_ne(c, NULL);

	_test_basic_cache(c);
}
END_TEST
#endif

START_TEST(test_cache_encrypt)
{
	bool rc = false;
	char *value = NULL;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	oauth2_crypto_passphrase_set(_log, NULL, "test-passphrase-1234");

	// encrypted cache: passphrase hashed with "none" + a hashed key
	rv = oauth2_cfg_set_cache(_log, NULL, "shm",
				  "name=enc_shm&encrypt=true&key_hash_algo="
				  "sha256&passphrase_hash_algo=none");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "enc_shm");
	ck_assert_ptr_ne(c, NULL);

	// round-trip: the value is encrypted on set and decrypted on get
	rc = oauth2_cache_set(_log, c, "mykey", "myvalue", 10);
	ck_assert_int_eq(rc, true);
	value = NULL;
	rc = oauth2_cache_get(_log, c, "mykey", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, NULL);
	ck_assert_str_eq(value, "myvalue");
	oauth2_mem_free(value);

	rc = oauth2_cache_set(_log, c, "mykey", NULL, 0);
	ck_assert_int_eq(rc, true);

	// a second encrypted cache using the default (SHA256) passphrase hash
	rv = oauth2_cfg_set_cache(_log, NULL, "shm",
				  "name=enc_shm2&encrypt=true");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "enc_shm2");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "k1", "v1", 10);
	ck_assert_int_eq(rc, true);
	value = NULL;
	rc = oauth2_cache_get(_log, c, "k1", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(value, "v1");
	oauth2_mem_free(value);
}
END_TEST

START_TEST(test_cache_obtain_and_child_init)
{
	bool rc = false;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	// obtaining a cache with no prior configuration auto-creates a default
	c = oauth2_cache_obtain(_log, NULL);
	ck_assert_ptr_ne(c, NULL);

	// child_init NULL guard
	rc = oauth2_cache_child_init(_log, NULL);
	ck_assert_int_eq(rc, false);

	// child_init dispatches to the shm backend
	rv = oauth2_cfg_set_cache(_log, NULL, "shm", "name=ci_shm");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "ci_shm");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_child_init(_log, c);
	ck_assert_int_eq(rc, true);

	// child_init dispatches to the file backend
	rv = oauth2_cfg_set_cache(_log, NULL, "file",
				  "name=ci_file&key_hash_algo=none");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "ci_file");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_child_init(_log, c);
	ck_assert_int_eq(rc, true);
}
END_TEST

START_TEST(test_cache_shm_eviction)
{
	bool rc = false;
	char *value = NULL;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	// expired-slot reuse: fill both slots and let them expire WITHOUT a
	// get() (so the keys are not cleaned), then a set() reuses an
	// expired slot
	rv = oauth2_cfg_set_cache(
	    _log, NULL, "shm", "name=evict&key_hash_algo=none&max_entries=2");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "evict");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "k0", "v0", 1);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(_log, c, "k1", "v1", 1);
	ck_assert_int_eq(rc, true);
	sleep(2);
	rc = oauth2_cache_set(_log, c, "k2", "v2", 60);
	ck_assert_int_eq(rc, true);
	value = NULL;
	rc = oauth2_cache_get(_log, c, "k2", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(value, "v2");
	oauth2_mem_free(value);

	// LRU eviction: both slots full+unexpired; touching one makes the other
	// least-recently-used and it is evicted by the next set()
	rv = oauth2_cfg_set_cache(_log, NULL, "shm",
				  "name=lru&key_hash_algo=none&max_entries=2");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "lru");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "alpha", "a", 60);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_set(_log, c, "beta", "b", 60);
	ck_assert_int_eq(rc, true);
	sleep(1);
	value = NULL;
	rc = oauth2_cache_get(_log, c, "alpha", &value);
	ck_assert_int_eq(rc, true);
	oauth2_mem_free(value);
	rc = oauth2_cache_set(_log, c, "gamma", "g", 60);
	ck_assert_int_eq(rc, true);
	value = NULL;
	rc = oauth2_cache_get(_log, c, "gamma", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(value, "g");
	oauth2_mem_free(value);
}
END_TEST

START_TEST(test_cache_key_too_long)
{
	bool rc = false;
	char *value = NULL;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	rv = oauth2_cfg_set_cache(
	    _log, NULL, "shm", "name=klen&key_hash_algo=none&max_key_size=8");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "klen");
	ck_assert_ptr_ne(c, NULL);

	// a key longer than the configured max_key_size is rejected by set();
	// get() must reject it the same way instead of reporting a cache miss
	const char *longkey = "key_longer_than_eight_chars";
	rc = oauth2_cache_set(_log, c, longkey, "v", 10);
	ck_assert_int_eq(rc, false);

	value = NULL;
	rc = oauth2_cache_get(_log, c, longkey, &value);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(value, NULL);
}
END_TEST

START_TEST(test_cache_file_dir)
{
	bool rc = false;
	char *value = NULL;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	// explicit "dir" option
	rv = oauth2_cfg_set_cache(
	    _log, NULL, "file",
	    "name=file_dir&key_hash_algo=none&dir=/tmp&clean_interval=60");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "file_dir");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "fk", "fv", 10);
	ck_assert_int_eq(rc, true);
	value = NULL;
	rc = oauth2_cache_get(_log, c, "fk", &value);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(value, "fv");
	oauth2_mem_free(value);

	// a non-existent directory makes the underlying fopen fail -> set false
	rv = oauth2_cfg_set_cache(_log, NULL, "file",
				  "name=file_baddir&key_hash_algo=none&dir=/no/"
				  "such/oauth2/dir&clean_interval=0");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "file_baddir");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "k", "v", 10);
	ck_assert_int_eq(rc, false);
}
END_TEST

#ifdef HAVE_LIBMEMCACHE
START_TEST(test_cache_memcache_options)
{
	bool rc = false;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	// explicit config_string + round-trip + child_init
	rv = oauth2_cfg_set_cache(
	    _log, NULL, "memcache",
	    "name=mc_cfg&config_string=--SERVER=127.0.0.1");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "mc_cfg");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "mk", "mv", 10);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_child_init(_log, c);
	ck_assert_int_eq(rc, true);
}
END_TEST
#endif

#ifdef HAVE_LIBHIREDIS
START_TEST(test_cache_redis_options)
{
	bool rc = false;
	char *value = NULL;
	oauth2_cache_t *c = NULL;
	char *rv = NULL;

	// explicit host/port + round-trip + child_init
	rv = oauth2_cfg_set_cache(_log, NULL, "redis",
				  "name=redis_hp&host=127.0.0.1&port=6379");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "redis_hp");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "rk", "rv", 10);
	ck_assert_int_eq(rc, true);
	rc = oauth2_cache_child_init(_log, c);
	ck_assert_int_eq(rc, true);

	// a dead port makes the connection fail -> set/get return false
	rv = oauth2_cfg_set_cache(_log, NULL, "redis",
				  "name=redis_dead&host=127.0.0.1&port=16399");
	ck_assert_ptr_eq(rv, NULL);
	c = oauth2_cache_obtain(_log, "redis_dead");
	ck_assert_ptr_ne(c, NULL);
	rc = oauth2_cache_set(_log, c, "x", "y", 10);
	ck_assert_int_eq(rc, false);
	value = NULL;
	rc = oauth2_cache_get(_log, c, "x", &value);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(value, NULL);
}
END_TEST
#endif

// the cache backends each have their own TTL-expiry mechanism (shm: in-process
// slot cleanup, file: file removal, memcache/redis: server-side), each tested
// with a real-time sleep(); registering one suite per backend lets them run
// concurrently (CK_RUN_SUITE=cache_file etc.) instead of serially

Suite *oauth2_check_cache_suite()
{
	Suite *s = suite_create("cache");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	// common + shm-backend tests
	tcase_add_test(c, test_cache_bogus);
	tcase_add_test(c, test_cache_shm);
	tcase_add_test(c, test_cache_encrypt);
	tcase_add_test(c, test_cache_obtain_and_child_init);
	tcase_add_test(c, test_cache_shm_eviction);
	tcase_add_test(c, test_cache_key_too_long);

	tcase_set_timeout(c, 12);

	suite_add_tcase(s, c);

	return s;
}

Suite *oauth2_check_cache_file_suite()
{
	Suite *s = suite_create("cache_file");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_cache_file);
	tcase_add_test(c, test_cache_file_dir);

	tcase_set_timeout(c, 12);

	suite_add_tcase(s, c);

	return s;
}

#ifdef HAVE_LIBMEMCACHE
Suite *oauth2_check_cache_memcache_suite()
{
	Suite *s = suite_create("cache_memcache");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_cache_memcache);
	tcase_add_test(c, test_cache_memcache_options);

	tcase_set_timeout(c, 12);

	suite_add_tcase(s, c);

	return s;
}
#endif

#ifdef HAVE_LIBHIREDIS
Suite *oauth2_check_cache_redis_suite()
{
	Suite *s = suite_create("cache_redis");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_cache_redis);
	tcase_add_test(c, test_cache_redis_options);

	tcase_set_timeout(c, 12);

	suite_add_tcase(s, c);

	return s;
}
#endif
