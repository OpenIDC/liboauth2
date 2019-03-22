#ifndef _OAUTH2_CHECK_LIBOAUTH2_H_
#define _OAUTH2_CHECK_LIBOAUTH2_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone IT BV - www.zmartzone.eu
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

//#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
//#pragma GCC diagnostic ignored
//"-Wincompatible-pointer-types-discards-qualifiers"
//#pragma GCC diagnostic ignored "-Wpointer-sign"

#include <check.h>

Suite *oauth2_check_version_suite();
Suite *oauth2_check_mem_suite();
Suite *oauth2_check_log_suite();
Suite *oauth2_check_util_suite();
Suite *oauth2_check_ipc_suite();
Suite *oauth2_check_cache_suite();
Suite *oauth2_check_jose_suite();
Suite *oauth2_check_http_suite();
Suite *oauth2_check_proto_suite();
Suite *oauth2_check_oauth2_suite();
Suite *oauth2_check_openidc_suite();

char *oauth2_check_http_serve(const char *request);
char *oauth2_check_jose_serve(const char *request);
char *oauth2_check_oauth2_serve(const char *request);

#define _ck_assert_bin(X, OP, Y, LEN)                                          \
	do {                                                                   \
		const uint8_t *_chk_x = (X);                                   \
		const uint8_t *_chk_y = (Y);                                   \
		const size_t _chk_len = (LEN);                                 \
		ck_assert_msg(0 OP memcmp(_chk_x, _chk_y, _chk_len),           \
			      "Assertion '" #X #OP #Y "' failed: " #LEN        \
			      "==%z, " #X "==0x%zx, " #Y "==0x%zx",            \
			      _chk_len, _chk_x, _chk_y);                       \
	} while (0);

#define ck_assert_bin_eq(X, Y, LEN) _ck_assert_bin(X, ==, Y, LEN)

#endif /* _OAUTH2_CHECK_LIBOAUTH2_H_ */
