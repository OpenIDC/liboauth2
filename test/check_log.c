/***************************************************************************
 *
 * Copyright (C) 2018-2022 - ZmartZone Holding BV - www.zmartzone.eu
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
#include "oauth2/log.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *_log = 0;

static void setup(void)
{
	// for coverage
	oauth2_log_free(NULL);
	_log = oauth2_log_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_log_free(_log);
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

static int check_log_test_sink_callback_dummy = 0;

static void
check_log_test_sink_callback(oauth2_log_sink_t *sink, const char *filename,
			     unsigned long line, const char *function,
			     oauth2_log_level_t level, const char *msg)
{
	check_log_test_sink_callback_dummy = 1;
}

START_TEST(test_sink)
{
	char *dummy = "dummy";
	oauth2_log_sink_t *sink = oauth2_log_sink_create(
	    OAUTH2_LOG_TRACE1, check_log_test_sink_callback, dummy);

	oauth2_log_sink_add(_log, sink);

	ck_assert_ptr_eq(oauth2_log_sink_callback_get(sink),
			 check_log_test_sink_callback);
	ck_assert_ptr_eq(oauth2_log_sink_ctx_get(sink), dummy);

	check_log_test_sink_callback_dummy = 0;
	oauth2_info(_log, "");
	ck_assert_int_eq(check_log_test_sink_callback_dummy, 1);
}
END_TEST

Suite *oauth2_check_log_suite()
{
	Suite *s = suite_create("log");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_log);
	tcase_add_test(c, test_sink);

	suite_add_tcase(s, c);

	return s;
}
