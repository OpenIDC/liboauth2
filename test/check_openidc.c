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

#include "oauth2/mem.h"
#include "oauth2/openidc.h"
#include "oauth2/util.h"

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

START_TEST(test_openidc_cfg)
{
	bool rc = false;
	oauth2_openidc_cfg_t *c = NULL;
	oauth2_http_request_t *r = NULL;
	oauth2_openidc_provider_t *p = NULL;
	char *value = NULL;

	c = oauth2_openidc_cfg_init(log);
	r = oauth2_http_request_init(log);

	rc = oauth2_openidc_cfg_redirect_uri_set(
	    log, c, "https://example.org/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_openidc_cfg_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.org/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_openidc_cfg_redirect_uri_set(
	    log, c, "https://example.com/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_openidc_cfg_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_openidc_cfg_redirect_uri_set(log, c, "/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_openidc_cfg_redirect_uri_get(log, c, r);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_http_request_hdr_in_set(log, r, "Host", "example.com");
	ck_assert_int_eq(rc, true);
	value = oauth2_openidc_cfg_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	p = oauth2_openidc_provider_init(log);
	ck_assert_ptr_ne(p, NULL);

	value = oauth2_openidc_cfg_redirect_uri_get_iss(log, c, r, p);
	// ck_assert_ptr_eq(value, NULL);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_openidc_provider_issuer_set(log, p, "jan");
	ck_assert_int_eq(rc, true);
	value = oauth2_openidc_cfg_redirect_uri_get_iss(log, c, r, p);
	ck_assert_str_eq(value, "https://example.com/redirect_uri?iss=jan");
	oauth2_mem_free(value);

	oauth2_openidc_provider_free(log, p);
	oauth2_http_request_free(log, r);
	oauth2_openidc_cfg_free(log, c);
}
END_TEST

Suite *oauth2_check_openidc_suite()
{
	Suite *s = suite_create("openidc");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_openidc_cfg);

	suite_add_tcase(s, c);

	return s;
}
