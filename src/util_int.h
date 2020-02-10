#ifndef _OAUTH2_UTIL_INT_H_
#define _OAUTH2_UTIL_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2020 - ZmartZone Holding BV - www.zmartzone.eu
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

#ifdef _MSC_VER
// not #if defined(_WIN32) || defined(_WIN64) because we have strncasecmp in
// mingw
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#define close _close
#endif

// need this for vasprintf with stdio.h
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "oauth2/log.h"
#include "oauth2/util.h"

/*
 * internal defines
 */

#define _OAUTH2_CHAR_COLON ':'
#define _OAUTH2_CHAR_QUERY '?'
#define _OAUTH2_CHAR_FSLASH '/'
#define _OAUTH2_CHAR_EQUAL '='
#define _OAUTH2_CHAR_SPACE ' '
#define _OAUTH2_CHAR_SEMICOL ';'
#define _OAUTH2_CHAR_AMP '&'
#define _OAUTH2_CHAR_DOT '.'
#define _OAUTH2_CHAR_COMMA ','

#define _OAUTH2_STR_COMMA ","
#define _OAUTH2_STR_COLON ":"
#define _OAUTH2_STR_QMARK "?"
#define _OAUTH2_STR_AMP "&"
#define _OAUTH2_STR_SEMICOL ";"
#define _OAUTH2_STR_EQUAL "="
#define _OAUTH2_STR_DOT "."

/*
 * internal generic (log) macros
 */

#define _OAUTH2_UTIL_JOSE_ERR_LOG(log, msg, err)                               \
	oauth2_error(log, "%s failed: [%s:%lu %s %s]", msg ? msg : "",         \
		     err.file ? err.file : "<n/a>", err.line,                  \
		     err.function ? err.function : "<n/a>",                    \
		     err.message ? err.message : "")

/*
 * struct type set/get macros
 */

#define _OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(module, object, member, type, name)  \
	bool oauth2_##module##_##object##_##member##_set(                      \
	    oauth2_log_t *log, oauth2_##module##_##object##_t *p,              \
	    const type v)                                                      \
	{                                                                      \
		return _oauth2_struct_slot_##name##_set(                       \
		    p, offsetof(oauth2_##module##_##object##_t, member), v);   \
	}

#define _OAUTH2_TYPE_IMPLEMENT_MEMBER_GET(module, object, member, type)        \
	type oauth2_##module##_##object##_##member##_get(                      \
	    oauth2_log_t *log, const oauth2_##module##_##object##_t *p)        \
	{                                                                      \
		if (p == NULL)                                                 \
			abort();                                               \
		return p->member;                                              \
	}

#define _OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(module, object, member, type,    \
					      name)                            \
	_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(module, object, member, type, name)  \
	_OAUTH2_TYPE_IMPLEMENT_MEMBER_GET(module, object, member, type)

/*
 * internal utility functions
 */

bool _oauth2_struct_slot_str_set(void *struct_ptr, size_t offset,
				 const char *value);
bool _oauth2_struct_slot_integer_set(void *struct_ptr, size_t offset,
				     const int value);
bool _oauth2_struct_slot_bln_set(void *struct_ptr, size_t offset,
				 const bool value);
bool _oauth2_struct_slot_ptr_set(void *struct_ptr, size_t offset,
				 const void *value);
bool _oauth2_struct_slot_uint_set(void *struct_ptr, size_t offset,
				  oauth2_uint_t value);
bool _oauth2_struct_slot_time_set(void *struct_ptr, size_t offset,
				  oauth2_time_t value);

char *_oauth2_stradd4(char *s1, const char *s2, const char *s3, const char *s4,
		      const char *s5);

bool _oauth2_nv_list_parse(oauth2_log_t *log, const char *input,
			   oauth2_nv_list_t *tuples, char sep_tuple,
			   char sep_nv, bool trim, bool url_decode);

char *_oauth2_bytes2str(oauth2_log_t *log, uint8_t *buf, size_t len);

/*
 * struct list member management macros
 */

#define _OAUTH2_MEMBER_LIST_IMPLEMENT_SET(module, type, list)                  \
	bool oauth2_##module##_##type##_##list##_set(                          \
	    oauth2_log_t *log, oauth2_##module##_##type##_t *r,                \
	    const char *name, const char *value)                               \
	{                                                                      \
		return r ? oauth2_nv_list_set(log, r->list, name, value)       \
			 : false;                                              \
	}

#define _OAUTH2_MEMBER_LIST_IMPLEMENT_UNSET(module, type, list)                \
	bool oauth2_##module##_##type##_##list##_unset(                        \
	    oauth2_log_t *log, oauth2_##module##_##type##_t *r,                \
	    const char *name)                                                  \
	{                                                                      \
		return r ? oauth2_nv_list_unset(log, r->list, name) : false;   \
	}

#define _OAUTH2_MEMBER_LIST_IMPLEMENT_ADD(module, type, list)                  \
	bool oauth2_##module##_##type##_##list##_add(                          \
	    oauth2_log_t *log, oauth2_##module##_##type##_t *r,                \
	    const char *name, const char *value)                               \
	{                                                                      \
		return r ? oauth2_nv_list_add(log, r->list, name, value)       \
			 : false;                                              \
	}

#define _OAUTH2_MEMBER_LIST_IMPLEMENT_GET(module, type, list)                  \
	const char *oauth2_##module##_##type##_##list##_get(                   \
	    oauth2_log_t *log, const oauth2_##module##_##type##_t *r,          \
	    const char *name)                                                  \
	{                                                                      \
		return r ? oauth2_nv_list_get(log, r->list, name) : NULL;      \
	}

#define _OAUTH2_MEMBER_LIST_IMPLEMENT_UNSET_GET(module, type, list)            \
	_OAUTH2_MEMBER_LIST_IMPLEMENT_UNSET(module, type, list)                \
	_OAUTH2_MEMBER_LIST_IMPLEMENT_GET(module, type, list)

#define _OAUTH2_MEMBER_LIST_IMPLEMENT_SET_ADD_UNSET_GET(module, type, list)    \
	_OAUTH2_MEMBER_LIST_IMPLEMENT_SET(module, type, list)                  \
	_OAUTH2_MEMBER_LIST_IMPLEMENT_UNSET_GET(module, type, list)            \
	_OAUTH2_MEMBER_LIST_IMPLEMENT_ADD(module, type, list)

#endif /* _OAUTH2_UTIL_INT_H_ */
