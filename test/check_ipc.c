/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
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

#include "check_liboauth2.h"
#include "oauth2/ipc.h"
#include "oauth2/mem.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *log = 0;

static void setup(void)
{
	log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(log);
}

START_TEST(test_sema)
{
	bool rc = false;
	oauth2_ipc_sema_t *s = NULL;

	s = oauth2_ipc_sema_init(log);
	ck_assert_ptr_ne(s, NULL);

	rc = oauth2_ipc_sema_post_config(log, s);
	ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_sema_post(log, s);
	ck_assert_int_eq(rc, true);
	rc = oauth2_ipc_sema_post(log, s);
	ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_sema_wait(log, s);
	ck_assert_int_eq(rc, true);
	rc = oauth2_ipc_sema_wait(log, s);
	ck_assert_int_eq(rc, true);
	// TODO: check for timeout
	// rc = oauth2_ipc_sema_wait(log, s);
	// ck_assert_int_eq(rc, true);

	oauth2_ipc_sema_free(log, s);
	s = NULL;
}
END_TEST

START_TEST(test_mutex)
{
	bool rc = false;
	oauth2_ipc_mutex_t *m = NULL;

	m = oauth2_ipc_mutex_init(log);
	ck_assert_ptr_ne(m, NULL);

	rc = oauth2_ipc_mutex_post_config(log, m);
	ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_mutex_lock(log, m);
	ck_assert_int_eq(rc, true);

	// TODO: check timeout
	// rc = oauth2_ipc_mutex_lock(log, m);
	// ck_assert_int_eq(rc, true);

	rc = oauth2_ipc_mutex_unlock(log, m);
	ck_assert_int_eq(rc, true);

	oauth2_ipc_mutex_free(log, m);
	m = NULL;
}
END_TEST

START_TEST(test_shm)
{
	bool rc = false;
	oauth2_ipc_shm_t *shm = NULL;
	void *ptr = NULL;

	shm = oauth2_ipc_shm_init(log, 256);
	ck_assert_ptr_ne(shm, NULL);

	rc = oauth2_ipc_shm_post_config(log, shm);
	ck_assert_int_eq(rc, true);

	ptr = oauth2_ipc_shm_get(log, shm);
	ck_assert_ptr_ne(ptr, NULL);

	oauth2_ipc_shm_free(log, shm);
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
