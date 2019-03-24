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

#include "oauth2/log.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *log = 0;

static void setup(void)
{
	// for coverage
	oauth2_log_free(NULL);
	log = oauth2_log_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_log_free(log);
}

START_TEST(test_log)
{
	// mostly to complete coverage

	// TODO: could return bytes written from oauth2_log statements
	oauth2_debug(NULL, NULL);
	// TOOD: could return bool from oauth2_log_sink_add
	oauth2_log_sink_add(log, &oauth2_log_sink_stderr);
	oauth2_info(log, NULL);
	oauth2_info(log, "");
	oauth2_log_sink_level_set(&oauth2_log_sink_stderr, OAUTH2_LOG_ERROR);
}
END_TEST

Suite *oauth2_check_log_suite()
{
	Suite *s = suite_create("log");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_log);

	suite_add_tcase(s, c);

	return s;
}
