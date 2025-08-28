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
#include "oauth2/ipc.h"
#include "oauth2/mem.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *_log = 0;

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(_log);
}

START_TEST(test_sema)
{
	bool rc = false;
	oauth2_ipc_sema_t *s = NULL;

	s = oauth2_ipc_sema_init(_log);
	ck_assert_ptr_ne(s, NULL);

	rc = oauth2_ipc_sema_post_config(_log, s);
	ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_sema_post(_log, s);
	ck_assert_int_eq(rc, true);
	rc = oauth2_ipc_sema_post(_log, s);
	ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_sema_wait(_log, s);
	ck_assert_int_eq(rc, true);
	rc = oauth2_ipc_sema_wait(_log, s);
	ck_assert_int_eq(rc, true);
	// TODO: check for timeout
	// rc = oauth2_ipc_sema_wait(_log, s);
	// ck_assert_int_eq(rc, true);

	oauth2_ipc_sema_free(_log, s);
	s = NULL;
}
END_TEST

START_TEST(test_mutex)
{
	bool rc = false;
	oauth2_ipc_mutex_t *m = NULL;

	m = oauth2_ipc_mutex_init(_log);
	ck_assert_ptr_ne(m, NULL);

	rc = oauth2_ipc_mutex_post_config(_log, m);
	ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_mutex_lock(_log, m);
	ck_assert_int_eq(rc, true);

	// TODO: check timeout
	// rc = oauth2_ipc_mutex_lock(_log, m);
	// ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_mutex_unlock(_log, m);
	ck_assert_int_eq(rc, true);

	oauth2_ipc_mutex_free(_log, m);
	m = NULL;
}
END_TEST

START_TEST(test_thread_mutex)
{
	bool rc = false;
	oauth2_ipc_thread_mutex_t *m = NULL;

	m = oauth2_ipc_thread_mutex_init(_log);
	ck_assert_ptr_ne(m, NULL);

	rc = oauth2_ipc_thread_mutex_lock(_log, m);
	ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_thread_mutex_unlock(_log, m);
	ck_assert_int_eq(rc, true);

	oauth2_ipc_thread_mutex_free(_log, m);
	m = NULL;
}
END_TEST

START_TEST(test_shm)
{
	bool rc = false;
	oauth2_ipc_shm_t *shm = NULL;
	void *ptr = NULL;

	shm = oauth2_ipc_shm_init(_log, 256);
	ck_assert_ptr_ne(shm, NULL);

	rc = oauth2_ipc_shm_post_config(_log, shm);
	ck_assert_int_eq(rc, true);

	ptr = oauth2_ipc_shm_get(_log, shm);
	ck_assert_ptr_ne(ptr, NULL);

	oauth2_ipc_shm_free(_log, shm);
	shm = NULL;
}
END_TEST

Suite *oauth2_check_ipc_suite()
{
	Suite *s = suite_create("ipc");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_sema);
	tcase_add_test(c, test_mutex);
	tcase_add_test(c, test_thread_mutex);
	tcase_add_test(c, test_shm);

	suite_add_tcase(s, c);

	return s;
}
