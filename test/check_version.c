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
#include "oauth2/mem.h"
#include "oauth2/util.h"
#include "oauth2/version.h"
#include <check.h>

START_TEST(test_version_defines)
{
	ck_assert_str_eq(OAUTH2_PACKAGE_VERSION, PACKAGE_VERSION);
	ck_assert_str_eq(OAUTH2_PACKAGE_NAME, PACKAGE_NAME);
}
END_TEST

START_TEST(test_version_function)
{
	const char *version = oauth2_version();
	ck_assert_str_eq(version, PACKAGE_VERSION);
}
END_TEST

START_TEST(test_package_string)
{
	const char *pkg_str = oauth2_package_string();
	ck_assert_str_eq(pkg_str, PACKAGE_NAME "-" PACKAGE_VERSION);
}
END_TEST

Suite *oauth2_check_version_suite()
{
	Suite *s = suite_create("version");
	TCase *c = tcase_create("core");

	tcase_add_test(c, test_version_defines);
	tcase_add_test(c, test_version_function);
	tcase_add_test(c, test_package_string);

	suite_add_tcase(s, c);

	return s;
}
