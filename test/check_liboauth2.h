#ifndef _OAUTH2_CHECK_LIBOAUTH2_H_
#define _OAUTH2_CHECK_LIBOAUTH2_H_

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

// #pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
// #pragma GCC diagnostic ignored
//"-Wincompatible-pointer-types-discards-qualifiers"
// #pragma GCC diagnostic ignored "-Wpointer-sign"

#include <check.h>

Suite *oauth2_check_version_suite();
Suite *oauth2_check_mem_suite();
Suite *oauth2_check_log_suite();
Suite *oauth2_check_cfg_suite();
Suite *oauth2_check_util_suite();
Suite *oauth2_check_ipc_suite();
Suite *oauth2_check_cache_suite();
Suite *oauth2_check_jose_suite();
void oauth2_check_jose_cleanup();
Suite *oauth2_check_http_suite();
void oauth2_check_http_cleanup();
Suite *oauth2_check_proto_suite();
void oauth2_check_proto_cleanup();
Suite *oauth2_check_oauth2_suite();
void oauth2_check_oauth2_cleanup();
Suite *oauth2_check_openidc_suite();
void oauth2_check_openidc_cleanup();
#ifdef HAVE_LIBJQ
Suite *oauth2_check_jq_suite();
#endif
#ifdef HAVE_APACHE
Suite *oauth2_check_apache_suite();
#endif
#ifdef HAVE_NGINX
Suite *oauth2_check_nginx_suite();
#endif

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

#ifndef _ck_assert_ptr
#define _ck_assert_ptr(X, OP, Y)                                               \
	do {                                                                   \
		const void *_ck_x = (X);                                       \
		const void *_ck_y = (Y);                                       \
		ck_assert_msg(_ck_x OP _ck_y,                                  \
			      "Assertion '%s' failed: %s == %#x, %s == %#x",   \
			      #X " " #OP " " #Y, #X, _ck_x, #Y, _ck_y);        \
	} while (0)
#define ck_assert_ptr_eq(X, Y) _ck_assert_ptr(X, ==, Y)
#define ck_assert_ptr_ne(X, Y) _ck_assert_ptr(X, !=, Y)
#endif

#ifndef _ck_assert_uint
#define _ck_assert_uint(X, OP, Y)                                              \
	do {                                                                   \
		uintmax_t _ck_x = (X);                                         \
		uintmax_t _ck_y = (Y);                                         \
		ck_assert_msg(_ck_x OP _ck_y,                                  \
			      "Assertion '%s' failed: %s == %ju, %s == %ju",   \
			      #X " " #OP " " #Y, #X, _ck_x, #Y, _ck_y);        \
	} while (0)
#define ck_assert_uint_eq(X, Y) _ck_assert_uint(X, ==, Y)
#define ck_assert_uint_ne(X, Y) _ck_assert_uint(X, !=, Y)
#endif

#endif /* _OAUTH2_CHECK_LIBOAUTH2_H_ */
