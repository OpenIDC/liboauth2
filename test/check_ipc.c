/***************************************************************************
 *
 * Copyright (C) 2018-2023 - ZmartZone Holding BV - www.zmartzone.eu
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
	tcase_add_test(c, test_shm);

	suite_add_tcase(s, c);

	return s;
}
