#ifndef _OAUTH2_CHECK_LIBOAUTH2_H_
#define _OAUTH2_CHECK_LIBOAUTH2_H_

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
#ifdef HAVE_APACHE
Suite *oauth2_check_apache_suite();
#endif
#ifdef HAVE_NGINX
Suite *oauth2_check_nginx_suite();
#endif

typedef char *(http_serve_callback_get_t)(const char *request);
typedef char *(http_serve_callback_post_t)(const char *request);
void liboauth2_check_register_http_callbacks(
    const char *path, http_serve_callback_get_t *get_cb,
    http_serve_callback_post_t *post_cb);

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

#define OAUTH2_CHECK_HTTP_PATHS                                                \
	static char *_http_base_path = NULL;                                   \
                                                                               \
	static char *oauth2_check_http_base_path()                             \
	{                                                                      \
		char *p = NULL, *path = NULL;                                  \
		if (_http_base_path == NULL) {                                 \
			path = oauth2_strdup(__FILE__);                        \
			p = strrchr(path, '.');                                \
			if (p)                                                 \
				*p = '\0';                                     \
			p = path;                                              \
			while (*p == '.') {                                    \
				p++;                                           \
				if (*p == '/')                                 \
					p++;                                   \
			}                                                      \
			if (*p == '/')                                         \
				p++;                                           \
			_http_base_path = oauth2_stradd(NULL, "/", p, NULL);   \
			oauth2_mem_free(path);                                 \
		}                                                              \
		return _http_base_path;                                        \
	}                                                                      \
                                                                               \
	static char *_http_base_url = NULL;                                    \
                                                                               \
	static char *oauth2_check_http_base_url()                              \
	{                                                                      \
		if (_http_base_url == NULL)                                    \
			_http_base_url = oauth2_stradd(                        \
			    NULL, "http://127.0.0.1:8888",                     \
			    oauth2_check_http_base_path(), NULL);              \
		return _http_base_url;                                         \
	}                                                                      \
                                                                               \
	static void oauth2_check_http_base_free()                              \
	{                                                                      \
		if (_http_base_url != NULL) {                                  \
			oauth2_mem_free(_http_base_url);                       \
			_http_base_url = NULL;                                 \
		}                                                              \
		if (_http_base_path != NULL) {                                 \
			oauth2_mem_free(_http_base_path);                      \
			_http_base_path = NULL;                                \
		}                                                              \
	}

#endif /* _OAUTH2_CHECK_LIBOAUTH2_H_ */
