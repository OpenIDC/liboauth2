/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
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
