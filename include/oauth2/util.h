#ifndef _OAUTH2_UTIL_H
#define _OAUTH2_UTIL_H

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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "oauth2/log.h"
#include <jansson.h>

#define OAUTH2_STRINGIFY(x) #x
#define OAUTH2_TOSTRING(x) OAUTH2_STRINGIFY(x)

typedef char oauth2_flag_t;
typedef unsigned int oauth2_uint_t;
typedef uint64_t oauth2_time_t;

#define OAUTH2_UINT_FORMAT "%u"
#define OAUTH2_TIME_T_FORMAT "%lu"

#define OAUTH2_MSEC_PER_SEC 1000
#define OAUTH2_USEC_PER_MSEC 1000

#define OAUTH2_TYPE_DECLARE(module, object)                                    \
	typedef struct oauth2_##module##_##object##_t                          \
	    oauth2_##module##_##object##_t;                                    \
	oauth2_##module##_##object##_t *oauth2_##module##_##object##_init(     \
	    oauth2_log_t *);                                                   \
	oauth2_##module##_##object##_t *oauth2_##module##_##object##_clone(    \
	    oauth2_log_t *, const oauth2_##module##_##object##_t *);           \
	void oauth2_##module##_##object##_free(                                \
	    oauth2_log_t *, oauth2_##module##_##object##_t *);

#define OAUTH2_TYPE_DECLARE_MEMBER_SET(module, object, member, type)           \
	bool oauth2_##module##_##object##_##member##_set(                      \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const type);

#define OAUTH2_TYPE_DECLARE_MEMBER_GET(module, object, member, type)           \
	type oauth2_##module##_##object##_##member##_get(                      \
	    oauth2_log_t *, const oauth2_##module##_##object##_t *);

#define OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(module, object, member, type)       \
	OAUTH2_TYPE_DECLARE_MEMBER_SET(module, object, member, type)           \
	OAUTH2_TYPE_DECLARE_MEMBER_GET(module, object, member, type)

#define OAUTH2_MEMBER_LIST_DECLARE_SET(module, object, member)                 \
	bool oauth2_##module##_##object##_##member##_set(                      \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const char *,    \
	    const char *);

#define OAUTH2_MEMBER_LIST_DECLARE_UNSET(module, object, member)               \
	bool oauth2_##module##_##object##_##member##_unset(                    \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const char *);

#define OAUTH2_MEMBER_LIST_DECLARE_ADD(module, object, member)                 \
	bool oauth2_##module##_##object##_##member##_add(                      \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const char *,    \
	    const char *);

#define OAUTH2_MEMBER_LIST_DECLARE_GET(module, object, member)                 \
	const char *oauth2_##module##_##object##_##member##_get(               \
	    oauth2_log_t *, const oauth2_##module##_##object##_t *,            \
	    const char *);

#define OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(module, object, member)   \
	OAUTH2_MEMBER_LIST_DECLARE_SET(module, object, member)                 \
	OAUTH2_MEMBER_LIST_DECLARE_UNSET(module, object, member)               \
	OAUTH2_MEMBER_LIST_DECLARE_ADD(module, object, member)                 \
	OAUTH2_MEMBER_LIST_DECLARE_GET(module, object, member)

#define OAUTH2_LIST_DECLARE_SET(module, type)                                  \
	bool oauth2_##module##_##type##_set(oauth2_log_t *,                    \
					    oauth2_##module##_##type##_t *,    \
					    const char *, const char *);

#define OAUTH2_LIST_DECLARE_UNSET(module, type)                                \
	bool oauth2_##module##_##type##_unset(                                 \
	    oauth2_log_t *, oauth2_##module##_##type##_t *, const char *);

#define OAUTH2_LIST_DECLARE_ADD(module, type)                                  \
	bool oauth2_##module##_##type##_add(oauth2_log_t *,                    \
					    oauth2_##module##_##type##_t *,    \
					    const char *, const char *);

#define OAUTH2_LIST_DECLARE_GET(module, type)                                  \
	const char *oauth2_##module##_##type##_get(                            \
	    oauth2_log_t *, const oauth2_##module##_##type##_t *,              \
	    const char *);

#define OAUTH2_LIST_DECLARE_SET_UNSET_ADD_GET(module, type)                    \
	OAUTH2_LIST_DECLARE_SET(module, type)                                  \
	OAUTH2_LIST_DECLARE_UNSET(module, type)                                \
	OAUTH2_LIST_DECLARE_ADD(module, type)                                  \
	OAUTH2_LIST_DECLARE_GET(module, type)

OAUTH2_TYPE_DECLARE(nv, list)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(nv, list, case_sensitive, bool)
OAUTH2_LIST_DECLARE_SET_UNSET_ADD_GET(nv, list)

typedef bool(oauth2_nv_list_loop_cb_t)(oauth2_log_t *log, void *rec,
				       const char *key, const char *value);
void oauth2_nv_list_loop(oauth2_log_t *log, const oauth2_nv_list_t *list,
			 oauth2_nv_list_loop_cb_t *callback, void *rec);
char *oauth2_nv_list2s(oauth2_log_t *log, const oauth2_nv_list_t *list);
void oauth2_nv_list_merge_into(oauth2_log_t *log,
			       const oauth2_nv_list_t *source,
			       oauth2_nv_list_t *target);

oauth2_log_t *oauth2_init(oauth2_log_level_t level, oauth2_log_sink_t *sink);
void oauth2_shutdown(oauth2_log_t *);

int oauth2_snprintf(char *dst, size_t len, const char *fmt, ...);
char *oauth2_strdup(const char *src);
char *oauth2_strndup(const char *src, size_t len);
char *oauth2_stradd(char *src, const char *add1, const char *add2,
		    const char *add3);
char *oauth2_getword(const char **line, char stop);

size_t oauth2_base64url_encode(oauth2_log_t *log, const uint8_t *src,
			       const size_t src_len, char **dst);
bool oauth2_base64url_decode(oauth2_log_t *log, const char *src, uint8_t **dst,
			     size_t *dst_len);
size_t oauth2_base64_encode(oauth2_log_t *log, const uint8_t *src,
			    const size_t src_len, char **dst);
bool oauth2_base64_decode(oauth2_log_t *log, const char *src, uint8_t **dst,
			  size_t *dst_len);

char *oauth2_url_encode(oauth2_log_t *log, const char *str);
char *oauth2_url_decode(oauth2_log_t *log, const char *str);

char *oauth2_html_escape(oauth2_log_t *log, const char *src);
bool oauth2_parse_form_encoded_params(oauth2_log_t *log, const char *data,
				      oauth2_nv_list_t **params);

bool oauth2_json_decode_check_error(oauth2_log_t *log, const char *str,
				    json_t **json);
bool oauth2_json_decode_object(oauth2_log_t *log, const char *payload,
			       json_t **json);
bool oauth2_json_object_get(oauth2_log_t *log, const json_t *json,
			    const char *name, json_t **value);
bool oauth2_json_string_get(oauth2_log_t *log, const json_t *json,
			    const char *name, char **value,
			    const char *default_value);
bool oauth2_json_number_get(oauth2_log_t *log, const json_t *json,
			    const char *name, json_int_t *number,
			    const json_int_t default_value);

char *oauth2_rand_str(oauth2_log_t *log, size_t len);
oauth2_time_t oauth2_time_now_sec();

oauth2_time_t oauth2_parse_time_sec(oauth2_log_t *log, const char *seconds,
				    oauth2_time_t default_value);
bool oauth2_parse_bool(oauth2_log_t *log, const char *value,
		       bool default_value);
oauth2_uint_t oauth2_parse_uint(oauth2_log_t *log, const char *int_value,
				oauth2_uint_t default_value);

int oauth2_strnenvcmp(const char *a, const char *b, int len);
char *oauth2_json_encode(oauth2_log_t *log, json_t *json, size_t flags);
char *oauth2_normalize_header_name(const char *str);

char *oauth_read_file(oauth2_log_t *log, const char *filename);

#endif /* _OAUTH2_UTIL_H */
