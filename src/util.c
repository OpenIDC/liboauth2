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

// need this at the top for vasprintf
#include "util_int.h"
#include <ctype.h>
#include <string.h>

#include "oauth2/log.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <cjose/base64.h>
#include <curl/curl.h>

#include "cache_int.h"
#include "cfg_int.h"

static CURL *_s_curl = NULL;
static oauth2_uint_t _curl_refcount = 0;

oauth2_log_t *oauth2_init(oauth2_log_level_t level, oauth2_log_sink_t *sink)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	// TODO: align flags/call with memory initialization in mem.c
	//       possibly providing alloc funcs as part of init?
	curl_global_init(CURL_GLOBAL_ALL);
	return oauth2_log_init(level, sink);
}

void oauth2_shutdown(oauth2_log_t *log)
{
	_oauth2_session_global_cleanup(log);
	_oauth2_cache_global_cleanup(log);

	if (_s_curl) {
		curl_easy_cleanup(_s_curl);
		_s_curl = NULL;
	}
	curl_global_cleanup();
	EVP_cleanup();
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();

//#if OPENSSL_API_COMPAT < 0x10100000L
//#if OPENSSL_VERSION_NUMBER < 0x10000000L
//	SSL_COMP_free_compression_methods();
//#endif
#if (OPENSSL_VERSION_NUMBER < 0x10100000) || defined(LIBRESSL_VERSION_NUMBER)
	//#if OPENSSL_API_COMPAT < 0x10100000L
	ERR_remove_thread_state(NULL);
#endif
	oauth2_log_free(log);
}

typedef bool(oauth2_cjose_base64_encode_callback_t)(const uint8_t *input,
						    const size_t inlen,
						    char **output,
						    size_t *outlen,
						    cjose_err *err);

static size_t _oauth2_cjose_base64_encode(
    oauth2_log_t *log, oauth2_cjose_base64_encode_callback_t encode,
    const uint8_t *src, const size_t src_len, char **dst)
{
	bool rc = false;
	size_t dst_len;
	cjose_err err;
	memset(&err, 0, sizeof(err));

	oauth2_debug(log, "enter: len=%d", (int)src_len);

	if (dst)
		*dst = NULL;
	dst_len = 0;

	if (src == NULL) {
		oauth2_warn(log, "not encoding null input to empty string");
		goto end;
	}

	rc = encode(src, src_len, dst, &dst_len, &err);
	if (!rc) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "encode", err);
		goto end;
	}

end:

	oauth2_debug(log, "leave: len=%d", (int)dst_len);

	return dst_len;
}

size_t oauth2_base64url_encode(oauth2_log_t *log, const uint8_t *src,
			       const size_t src_len, char **dst)
{
	return _oauth2_cjose_base64_encode(log, cjose_base64url_encode, src,
					   src_len, dst);
}

size_t oauth2_base64_encode(oauth2_log_t *log, const uint8_t *src,
			    const size_t src_len, char **dst)
{
	return _oauth2_cjose_base64_encode(log, cjose_base64_encode, src,
					   src_len, dst);
}

typedef bool(oauth2_cjose_base64_decode_callback_t)(const char *input,
						    const size_t inlen,
						    uint8_t **output,
						    size_t *outlen,
						    cjose_err *err);

static bool
_oauth2_cjose_base64_decode(oauth2_log_t *log,
			    oauth2_cjose_base64_decode_callback_t decode,
			    const char *src, uint8_t **dst, size_t *dst_len)
{
	bool rc = false;
	cjose_err err;
	size_t src_len = 0;

	memset(&err, 0, sizeof(err));
	src_len = src ? strlen(src) : 0;

	oauth2_debug(log, "enter: len=%d", (int)src_len);

	if (dst == NULL)
		goto end;
	*dst = NULL;

	if (dst_len == NULL)
		goto end;
	*dst_len = 0;

	if (src == NULL) {
		oauth2_warn(log, "not decoding null input");
		goto end;
	}

	if (decode(src, src_len, dst, dst_len, &err) == false) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "decode", err);
		goto end;
	}

	rc = true;

end:

	oauth2_debug(log, "leave: len=%d", (dst_len) ? (int)*dst_len : -1);

	return rc;
}

bool oauth2_base64url_decode(oauth2_log_t *log, const char *src, uint8_t **dst,
			     size_t *dst_len)
{
	return _oauth2_cjose_base64_decode(log, cjose_base64url_decode, src,
					   dst, dst_len);
}

bool oauth2_base64_decode(oauth2_log_t *log, const char *src, uint8_t **dst,
			  size_t *dst_len)
{
	return _oauth2_cjose_base64_decode(log, cjose_base64_decode, src, dst,
					   dst_len);
}

static int oauth2_char_to_env(int c)
{
	return isalnum(c) ? toupper(c) : '_';
}

int oauth2_strnenvcmp(const char *a, const char *b, int len)
{
	int rv = 0;
	int d, i = 0;

	while (1) {

		// if len < 0 then we don't stop based on length
		if (len >= 0 && i >= len)
			goto end;

		// if we're at the end of both strings, they're equal
		if (!*a && !*b)
			goto end;

		// if the second string is shorter, pick it:
		if (*a && !*b) {
			rv = 1;
			goto end;
		}

		// if the first string is shorter, pick it:
		if (!*a && *b) {
			rv = -1;
			goto end;
		}

		// normalize the characters as for conversion to an environment
		// variable.
		d = oauth2_char_to_env(*a) - oauth2_char_to_env(*b);
		if (d) {
			rv = d;
			goto end;
		}

		a++;
		b++;
		i++;
	}

end:

	return rv;
}

static CURL *oauth2_curl_init(oauth2_log_t *log)
{
	if (_s_curl == NULL) {
		_s_curl = curl_easy_init();
		if (_s_curl == NULL) {
			oauth2_error(log, "curl_easy_init() error");
		}
	}
	_curl_refcount++;
	return _s_curl;
}

static void oauth2_curl_free(CURL *curl)
{
	_curl_refcount--;
	if ((_curl_refcount == 0) && (_s_curl)) {
		curl_easy_cleanup(_s_curl);
		_s_curl = NULL;
	}
}

char *oauth2_url_encode(oauth2_log_t *log, const char *src)
{
	char *dst = NULL, *rc = NULL;
	CURL *curl = NULL;

	oauth2_debug(log, "enter: %s", src);

	if (src == NULL) {
		oauth2_warn(log, "not encoding empty string");
		goto end;
	}

	curl = oauth2_curl_init(log);
	if (curl == NULL)
		goto end;

	rc = curl_easy_escape(curl, src, strlen(src));
	if (rc == NULL) {
		oauth2_error(log, "curl_easy_escape() error");
		goto end;
	}

	dst = oauth2_strdup(rc);

end:
	if (rc)
		curl_free(rc);
	if (curl)
		oauth2_curl_free(curl);

	oauth2_debug(log, "leave: %s", dst);

	return dst;
}

char *oauth2_url_decode(oauth2_log_t *log, const char *src)
{
	char *dst = NULL, *rc = NULL;
	char *replaced = NULL;
	CURL *curl = NULL;
	int i = 0;

	oauth2_debug(log, "enter: %s", src);

	if (src == NULL) {
		oauth2_warn(log, "not decoding empty string");
		goto end;
	}

	curl = oauth2_curl_init(log);
	if (curl == NULL)
		goto end;

	replaced = oauth2_strdup(src);
	if (replaced == NULL)
		goto end;

	// https://github.com/unshiftio/querystringify/issues/7#issuecomment-287627341
	for (i = 0; replaced[i] != '\0'; i++)
		if (replaced[i] == '+')
			// NOTE: technically it would be more correct to make
			// this a %20...
			replaced[i] = ' ';

	rc = curl_easy_unescape(curl, replaced, strlen(replaced), NULL);
	if (rc == NULL) {
		oauth2_error(log, "curl_easy_unescape() error");
		goto end;
	}

	dst = oauth2_strdup(rc);

end:
	if (rc)
		curl_free(rc);
	if (replaced)
		oauth2_mem_free(replaced);
	if (curl)
		oauth2_curl_free(curl);

	oauth2_debug(log, "leave: %s", dst);

	return dst;
}

// TODO: this has performance/memory issues for large chunks of HTML
char *oauth2_html_escape(oauth2_log_t *log, const char *src)
{
	char *dst = NULL, *rc = NULL;
	const char escape_chars[6] = {'&', '\'', '\"', '>', '<', '\0'};
	const char *const replace_chars[] = {"&amp;", "&apos;", "&quot;",
					     "&gt;", "&lt;"};
	unsigned int i, j = 0, k, n = 0,
			escape_chars_len = strlen(escape_chars);
	size_t m = 0, src_len = src ? strlen(src) : 0;

	oauth2_debug(log, "enter: %s", src);

	if (src == NULL)
		goto end;

	rc = oauth2_mem_alloc(src_len * 6 + 1);
	for (i = 0; i < src_len; i++) {
		for (n = 0; n < escape_chars_len; n++) {
			if (src[i] == escape_chars[n]) {
				m = strlen(replace_chars[n]);
				for (k = 0; k < m; k++)
					rc[j + k] = replace_chars[n][k];
				j += m;
				break;
			}
		}
		if (n == escape_chars_len) {
			rc[j] = src[i];
			j++;
		}
	}
	rc[j] = '\0';

	dst = oauth2_strdup(rc);

end:
	if (rc)
		oauth2_mem_free(rc);

	oauth2_debug(log, "leave: %s", dst);

	return dst;
}

static char *_oauth2_trim(char *src)
{
	char *rv = NULL;
	char *start = NULL, *end = NULL;
	char *buf = NULL;

	if (src == NULL)
		goto end;

	buf = oauth2_strdup(src);
	start = buf;

	while (isspace(*start))
		++start;
	end = &start[strlen(start)];
	while (--end >= start && isspace(*end))
		*end = '\0';

	rv = oauth2_strdup(start);

end:
	if (buf)
		oauth2_mem_free(buf);

	return rv;
}

char *oauth2_getword(const char **line, char stop)
{
	const char *pos = *line;
	int len;
	char *res;

	while ((*pos != stop) && *pos) {
		++pos;
	}

	len = pos - *line;
	res = oauth2_strndup(*line, len);

	if (stop) {
		while (*pos == stop) {
			++pos;
		}
	}
	*line = pos;

	return res;
}

bool _oauth2_nv_list_parse(oauth2_log_t *log, const char *input,
			   oauth2_nv_list_t *tuples, char sep_tuple,
			   char sep_nv, bool trim, bool url_decode)
{
	bool rc = false;
	const char *p = NULL;
	char *save_input = NULL, *save_val = NULL;
	char *key = NULL, *val = NULL;
	char *dec_key = NULL, *dec_val = NULL;
	char *trm_key = NULL, *trm_val = NULL;

	if ((input == NULL) || (tuples == NULL))
		goto end;

	save_input = oauth2_strdup(input);
	p = save_input;

	while (p && *p && (val = oauth2_getword(&p, sep_tuple))) {

		save_val = val;
		key = oauth2_getword((const char **)&val, sep_nv);

		if (key == NULL)
			continue;

		trm_key = trim ? _oauth2_trim(key) : oauth2_strdup(key);
		trm_val = trim ? _oauth2_trim(val) : oauth2_strdup(val);

		if (url_decode) {
			dec_key = oauth2_url_decode(log, trm_key);
			dec_val = oauth2_url_decode(log, trm_val);
			oauth2_nv_list_add(log, tuples, dec_key, dec_val);
			oauth2_mem_free(dec_key);
			oauth2_mem_free(dec_val);
		} else {
			oauth2_nv_list_add(log, tuples, trm_key, trm_val);
		}

		oauth2_mem_free(trm_key);
		if (trm_val)
			oauth2_mem_free(trm_val);
		oauth2_mem_free(key);
		if (save_val)
			oauth2_mem_free(save_val);
	}

	rc = true;

end:

	if (save_input)
		oauth2_mem_free(save_input);

	return rc;
}

bool oauth2_parse_form_encoded_params(oauth2_log_t *log, const char *data,
				      oauth2_nv_list_t **params)
{
	bool rc = false;

	if (params == NULL)
		goto end;

	if (data == NULL) {
		rc = true;
		goto end;
	}

	*params = oauth2_nv_list_init(log);
	if (*params == NULL)
		goto end;

	rc = _oauth2_nv_list_parse(log, data, *params, _OAUTH2_CHAR_AMP,
				   _OAUTH2_CHAR_EQUAL, false, true);

end:

	return rc;
}

/*
 * internal
 */

char *oauth2_strndup(const char *src, size_t len)
{
	char *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_mem_alloc(len + 1);
	if (dst == NULL)
		goto end;

	memcpy(dst, src, len);
	dst[len] = '\0';

end:

	return dst;
}

char *oauth2_strdup(const char *src)
{
	return oauth2_strndup(src, src ? strlen(src) : 0);
}

char *_oauth2_stradd4(char *src, const char *add1, const char *add2,
		      const char *add3, const char *add4)
{
	char *ptr = NULL;
	size_t len = 0;

	if (src == NULL)
		src = oauth2_strdup("");
	if (src == NULL)
		goto end;

	if (add1 == NULL)
		add1 = "";
	if (add2 == NULL)
		add2 = "";
	if (add3 == NULL)
		add3 = "";
	if (add4 == NULL)
		add4 = "";

	len = strlen(src) + strlen(add1) + strlen(add2) + strlen(add3) +
	      strlen(add4) + 1;

	ptr = oauth2_mem_alloc(len);
	if (ptr == NULL)
		goto end;

	oauth2_snprintf(ptr, len, "%s%s%s%s%s", src, add1, add2, add3, add4);

end:

	if (src)
		oauth2_mem_free(src);

	return ptr;
}

char *oauth2_stradd(char *src, const char *add1, const char *add2,
		    const char *add3)
{
	return _oauth2_stradd4(src, add1, add2, add3, NULL);
}

static bool _oauth2_nv2s(oauth2_log_t *log, void *rec, const char *key,
			 const char *value)
{
	bool rc = false;
	char **str = (char **)rec;

	if (str == NULL)
		goto end;

	*str = _oauth2_stradd4(*str, " ", key, _OAUTH2_STR_EQUAL, value);

	rc = true;

end:

	return rc;
}

char *oauth2_nv_list2s(oauth2_log_t *log, const oauth2_nv_list_t *list)
{
	char *str = oauth2_strdup("[");
	oauth2_nv_list_loop(log, list, _oauth2_nv2s, &str);
	str = oauth2_stradd(str, " ]", NULL, NULL);
	return str;
}

bool _oauth2_struct_slot_str_set(void *struct_ptr, size_t offset,
				 const char *value)
{
	bool rc = false;
	char *base = NULL, **ptr = NULL;

	if ((struct_ptr == NULL) || (value == NULL))
		goto end;

	base = (char *)struct_ptr;
	ptr = (char **)(base + offset);

	if (*ptr)
		oauth2_mem_free(*ptr);
	*ptr = oauth2_strdup(value);

	rc = (*ptr != NULL);

end:

	return rc;
}

#define _OAUTH2_STRUCT_MEMBER_SET(name, type)                                  \
	bool _oauth2_struct_slot_##name##_set(void *struct_ptr, size_t offset, \
					      const type value)                \
	{                                                                      \
		bool rc = false;                                               \
		char *base = NULL;                                             \
		type *ptr = NULL;                                              \
                                                                               \
		if (struct_ptr == NULL)                                        \
			goto end;                                              \
                                                                               \
		base = (char *)struct_ptr;                                     \
		ptr = (type *)(base + offset);                                 \
                                                                               \
		*ptr = value;                                                  \
                                                                               \
		rc = true;                                                     \
                                                                               \
	end:                                                                   \
                                                                               \
		return rc;                                                     \
	}

_OAUTH2_STRUCT_MEMBER_SET(bln, bool)
_OAUTH2_STRUCT_MEMBER_SET(integer, int)
_OAUTH2_STRUCT_MEMBER_SET(uint, oauth2_uint_t)
_OAUTH2_STRUCT_MEMBER_SET(time, oauth2_time_t)

bool _oauth2_struct_slot_ptr_set(void *struct_ptr, size_t offset,
				 const void *value)
{
	bool rc = false;
	char *base = NULL;
	void **ptr = NULL;

	if (struct_ptr == NULL)
		goto end;

	base = (char *)struct_ptr;
	ptr = (void **)(base + offset);

	// TODO: should probably make a typed definition for nv_list to free
	// here if already set...
	*ptr = (void *)value;

	rc = true;

end:

	return rc;
}

int oauth2_snprintf(char *dst, size_t len, const char *fmt, ...)
{
	va_list ap;
	int rc = 0;

	if ((dst == NULL) || (fmt == NULL))
		goto end;

	va_start(ap, fmt);
	rc = vsnprintf(dst, len, fmt, ap);
	va_end(ap);

end:

	return rc;
}

/*
 * name value pairs/list stuff
 */

typedef struct _oauth2_nv_t {
	char *name;
	char *value;
	struct _oauth2_nv_t *next;
} _oauth2_nv_t;

static _oauth2_nv_t *_oauth2_nv_new(oauth2_log_t *log, const char *name,
				    const char *value)
{
	_oauth2_nv_t *ptr = NULL;
	ptr = oauth2_mem_alloc(sizeof(_oauth2_nv_t));
	if (ptr != NULL) {
		ptr->name = name ? oauth2_strdup(name) : NULL;
		ptr->value = value ? oauth2_strdup(value) : NULL;
		ptr->next = NULL;
	}
	return ptr;
}

static void _oauth2_nv_free(oauth2_log_t *log, _oauth2_nv_t *ptr)
{
	if (ptr->name)
		oauth2_mem_free(ptr->name);
	if (ptr->value)
		oauth2_mem_free(ptr->value);
	oauth2_mem_free(ptr);
}

typedef struct oauth2_nv_list_t {
	_oauth2_nv_t *first;
	bool case_sensitive;
} oauth2_nv_list_t;

oauth2_nv_list_t *oauth2_nv_list_init(oauth2_log_t *log)
{
	oauth2_nv_list_t *ptr = NULL;
	ptr = oauth2_mem_alloc(sizeof(oauth2_nv_list_t));
	if (ptr != NULL) {
		ptr->case_sensitive = true;
	}
	return ptr;
}

void oauth2_nv_list_free(oauth2_log_t *log, oauth2_nv_list_t *list)
{
	_oauth2_nv_t *ptr = NULL;

	if (list == NULL)
		goto end;

	while ((ptr = list->first)) {
		list->first = list->first->next;
		_oauth2_nv_free(log, ptr);
	}

	oauth2_mem_free(list);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(nv, list, case_sensitive, bool, bln)

static bool _oauth2_nv_list_find(oauth2_log_t *log,
				 const oauth2_nv_list_t *list, const char *name,
				 _oauth2_nv_t **ptr, _oauth2_nv_t **prev)
{
	bool rc = false;

	if ((list == NULL) || (name == NULL))
		goto end;

	for (*ptr = list->first; *ptr; *ptr = (*ptr)->next) {
		if (list->case_sensitive) {
			if (strcmp((*ptr)->name, name) == 0) {
				rc = true;
				break;
			}
		} else {
			if (strcasecmp((*ptr)->name, name) == 0) {
				rc = true;
				break;
			}
		}
		*prev = *ptr;
	}

end:

	return rc;
}

bool oauth2_nv_list_set(oauth2_log_t *log, oauth2_nv_list_t *list,
			const char *name, const char *value)
{
	bool rc = false;
	_oauth2_nv_t *ptr = NULL, *prev = NULL;

	if ((list == NULL) || (name == NULL))
		goto end;

	_oauth2_nv_list_find(log, list, name, &ptr, &prev);

	if (ptr == NULL) {
		rc = oauth2_nv_list_add(log, list, name, value);
		goto end;
	}

	if (ptr->value)
		oauth2_mem_free(ptr->value);

	ptr->value = value ? oauth2_strdup(value) : NULL;

	rc = true;

end:

	return rc;
}

bool oauth2_nv_list_unset(oauth2_log_t *log, oauth2_nv_list_t *list,
			  const char *name)
{
	bool rc = false;
	_oauth2_nv_t *ptr = NULL, *prev = NULL;

	if ((list == NULL) || (name == NULL))
		goto end;

	_oauth2_nv_list_find(log, list, name, &ptr, &prev);

	if (ptr) {
		if (prev)
			prev->next = ptr->next;
		else
			list->first = ptr->next;
		_oauth2_nv_free(log, ptr);
	}

	rc = true;

end:

	return rc;
}

bool oauth2_nv_list_add(oauth2_log_t *log, oauth2_nv_list_t *list,
			const char *name, const char *value)
{
	bool rc = false;
	_oauth2_nv_t *ptr = NULL, *prev = NULL;

	if ((list == NULL) || (name == NULL))
		goto end;

	ptr = _oauth2_nv_new(log, name, value);
	if (ptr == NULL)
		goto end;

	if (list->first == NULL) {
		list->first = ptr;
	} else {
		for (prev = list->first; prev->next; prev = prev->next)
			;
		prev->next = ptr;
	}

	rc = true;

end:

	return rc;
}

const char *oauth2_nv_list_get(oauth2_log_t *log, const oauth2_nv_list_t *list,
			       const char *name)
{
	const char *value = NULL;
	_oauth2_nv_t *ptr = NULL, *prev = NULL;

	if ((list == NULL) || (name == NULL))
		goto end;

	_oauth2_nv_list_find(log, list, name, &ptr, &prev);

	if (ptr)
		value = ptr->value;

end:

	if (name != NULL)
		oauth2_debug(log, "%s=%s", name, value ? value : "(null)");

	return value;
}

void oauth2_nv_list_loop(oauth2_log_t *log, const oauth2_nv_list_t *list,
			 oauth2_nv_list_loop_cb_t *callback, void *rec)
{
	_oauth2_nv_t *ptr = NULL;

	if ((list == NULL) || (callback == NULL))
		goto end;

	for (ptr = list->first; ptr; ptr = ptr->next) {
		if (callback(log, rec, ptr->name, ptr->value) == false)
			break;
	}

end:

	return;
}

static bool _oauth2_nv_list_copy(oauth2_log_t *log, void *rec, const char *key,
				 const char *value)
{
	oauth2_nv_list_t *dst = (oauth2_nv_list_t *)rec;
	return oauth2_nv_list_add(log, dst, key, value);
}

oauth2_nv_list_t *oauth2_nv_list_clone(oauth2_log_t *log,
				       const oauth2_nv_list_t *src)
{
	oauth2_nv_list_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_nv_list_init(log);
	if (dst == NULL)
		goto end;

	if (oauth2_nv_list_case_sensitive_set(
		log, dst, oauth2_nv_list_case_sensitive_get(log, src)) == false)
		goto end;

	oauth2_nv_list_loop(log, src, _oauth2_nv_list_copy, dst);

end:

	return dst;
}

void oauth2_nv_list_merge_into(oauth2_log_t *log,
			       const oauth2_nv_list_t *source,
			       oauth2_nv_list_t *target)
{
	if (source) {
		oauth2_nv_list_loop(log, source, _oauth2_nv_list_copy, target);
	}
}

/*
 * JSON
 */

bool oauth2_json_decode_object(oauth2_log_t *log, const char *payload,
			       json_t **json)
{
	bool rc = false;
	json_error_t err;

	*json = json_loads(payload, 0, &err);
	if (*json == NULL) {
		oauth2_error(log, "json_loads failed: %s", err.text);
		goto end;
	}

	if (*json == NULL) {
		oauth2_error(log, "JSON parsing returned an error: %s (%s)",
			     err.text, payload);
		goto end;
	}

	if (!json_is_object(*json)) {
		oauth2_error(log, "parsed JSON did not contain a JSON object");
		json_decref(*json);
		*json = NULL;
		goto end;
	}

	rc = true;

end:

	return rc;
}

bool oauth2_json_object_get(oauth2_log_t *log, const json_t *json,
			    const char *name, json_t **value)
{
	bool rc = false;
	json_t *v = NULL;

	if ((json == NULL) || (name == NULL) || (value == NULL))
		goto end;

	v = json_object_get(json, name);
	if (v == NULL)
		goto end;

	if (json_is_null(v)) {
		rc = true;
		goto end;
	}

	if (!json_is_object(v)) {
		oauth2_warn(log, "found a non-object object with key: \"%s\"",
			    name);
		goto end;
	}

	json_incref(v);
	*value = v;
	rc = true;

end:

	return rc;
}

bool oauth2_json_string_get(oauth2_log_t *log, const json_t *json,
			    const char *name, char **value,
			    const char *default_value)
{
	bool rc = false;
	json_t *v = NULL;

	if ((json == NULL) || (name == NULL) || (value == NULL)) {
		if (default_value)
			*value = oauth2_strdup(default_value);
		goto end;
	}

	v = json_object_get(json, name);
	if (v == NULL) {
		if (default_value)
			*value = oauth2_strdup(default_value);
		rc = true;
		goto end;
	}

	if (json_is_null(v)) {
		rc = true;
		goto end;
	}

	if (!json_is_string(v)) {
		oauth2_warn(log, "found a non-string object with key: \"%s\"",
			    name);
		goto end;
	}

	*value = oauth2_strdup(json_string_value(v));
	rc = true;

end:

	return rc;
}

bool oauth2_json_number_get(oauth2_log_t *log, const json_t *json,
			    const char *name, json_int_t *number,
			    const json_int_t default_value)
{
	bool rc = false;
	json_t *v = NULL;

	if ((json == NULL) || (name == NULL) || (number == NULL)) {
		*number = default_value;
		goto end;
	}

	v = json_object_get(json, name);
	if (v == NULL) {
		*number = default_value;
		rc = true;
		goto end;
	}

	if (json_is_null(v)) {
		*number = default_value;
		rc = true;
		goto end;
	}

	if (!json_is_number(v)) {
		oauth2_warn(log, "found a non-number object with key: \"%s\"",
			    name);
		goto end;
	}

	*number = json_integer_value(v);
	rc = true;

end:

	return rc;
}

char *oauth2_json_encode(oauth2_log_t *log, json_t *json, size_t flags)
{
	char *s = json_dumps(json, flags);
	char *s_value = oauth2_strdup(s);
	free(s);
	return s_value;
}

static bool oauth2_json_string_print(oauth2_log_t *log, json_t *result,
				     const char *key, const char *msg)
{
	bool rc = false;
	json_t *value = NULL;
	char *str = NULL;

	value = json_object_get(result, key);

	if ((value != NULL) && (!json_is_null(value))) {
		str = oauth2_json_encode(log, value, JSON_ENCODE_ANY);
		oauth2_error(log,
			     "%s: response contained an \"%s\" entry with "
			     "value: \"%s\"",
			     msg, key,
			     oauth2_json_encode(log, value, JSON_ENCODE_ANY));
		oauth2_mem_free(str);
		rc = true;
	}

	return rc;
}

static bool oauth2_json_check_error(oauth2_log_t *log, json_t *json)
{
	bool rc = false;
	if (oauth2_json_string_print(log, json, "error",
				     "oidc_util_check_json_error") == true) {
		oauth2_json_string_print(log, json, "error_description",
					 "oidc_util_check_json_error");
		rc = true;
	}
	return rc;
}

bool oauth2_json_decode_check_error(oauth2_log_t *log, const char *str,
				    json_t **json)
{
	bool rc = false;

	if (oauth2_json_decode_object(log, str, json) == false)
		goto end;

	if (oauth2_json_check_error(log, *json) == true) {
		json_decref(*json);
		*json = NULL;
		goto end;
	}

	rc = true;

end:

	return rc;
}

/*
 * other
 */

#define OAUTH2_RANDOM_BUFSIZE 4096

bool _oauth2_rand_bytes(oauth2_log_t *log, uint8_t *buf, size_t len)
{
	bool rc = true;
	int chunk = 0;
	uint8_t *ptr = buf;

	while (len > 0) {
		chunk =
		    len < OAUTH2_RANDOM_BUFSIZE ? len : OAUTH2_RANDOM_BUFSIZE;
		if (RAND_bytes(ptr, chunk) <= 0) {
			oauth2_error(log, "could not generate random bytes %d",
				     chunk);
			rc = false;
			break;
		}
		len -= chunk;
		ptr += chunk;
	}

	return rc;
}

char *_oauth2_bytes2str(oauth2_log_t *log, uint8_t *buf, size_t len)
{
	char *rv = NULL, *ptr = NULL;
	int i = 0, n = 0;

	rv = oauth2_mem_alloc(len * 2 + 1);
	if (rv == NULL)
		goto end;

	ptr = rv;
	for (i = 0; i < len; i++) {
		n = oauth2_snprintf(ptr, 3, "%02x", buf[i]);
		if (n != 2) {
			oauth2_error(log, "could not oauth2_snprintf byte %d",
				     i);
			oauth2_mem_free(rv);
			rv = NULL;
			goto end;
		}
		ptr += 2;
	}
	rv[len * 2] = '\0';

end:

	return rv;
}

char *oauth2_rand_str(oauth2_log_t *log, size_t len)
{
	char *rv = NULL;
	uint8_t *buf = NULL;
	size_t half_len = 0;

	if (len == 0)
		goto end;

	half_len = len / 2 + 1;
	buf = oauth2_mem_alloc(half_len);
	if (buf == NULL)
		goto end;

	if (_oauth2_rand_bytes(log, buf, half_len) == false)
		goto end;

	rv = _oauth2_bytes2str(log, buf, half_len);
	// need this if len is uneven
	rv[len] = '\0';

end:

	if (buf)
		oauth2_mem_free(buf);

	// oauth2_error(log, " ## returning: %s (%lu)", rv, len);

	return rv;
}
/*

char *oauth2_rand_str(oauth2_log_t *log, size_t len)
{
	char *rv = NULL;
	bool rc = 0;
	uint8_t *buf = NULL;

	if (len == 0)
		goto end;

	buf = oauth2_mem_alloc(len);
	if (buf == NULL)
		goto end;

	rc = _oauth2_rand_bytes(log, buf, len);
	if (rc == false)
		goto end;

	oauth2_base64url_encode(log, (const uint8_t *)buf, len, &rv);

	if (rv)
		rv[len] = '\0';

end:

	if (buf)
		oauth2_mem_free(buf);

	// oauth2_error(log, " ## returning: %s (%lu)", rv, len);

	return rv;
}

*/

#ifdef _MSC_VER

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h> // portable: uint64_t   MSVC: __int64

// MSVC defines this in winsock2.h!?
// typedef struct timeval {
//	long tv_sec;
//	long tv_usec;
//} timeval;

int gettimeofday(struct timeval *tp, struct timezone *tzp)
{
	// Note: some broken versions only have 8 trailing zero's, the correct
	// epoch has 9 trailing zero's This magic number is the number of 100
	// nanosecond intervals since January 1, 1601 (UTC) until 00:00:00
	// January 1, 1970
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME system_time;
	FILETIME file_time;
	uint64_t time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}
#endif

static oauth2_time_t _oauth2_time_now_ms()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * (uint64_t)OAUTH2_MSEC_PER_SEC) +
	       (tv.tv_usec / OAUTH2_USEC_PER_MSEC);
}

oauth2_time_t oauth2_time_now_sec()
{
	return _oauth2_time_now_ms() / OAUTH2_MSEC_PER_SEC;
}

oauth2_time_t oauth2_parse_time_sec(oauth2_log_t *log, const char *seconds,
				    oauth2_time_t default_value)
{
	oauth2_time_t result = default_value;
	if (seconds)
		result = (oauth2_time_t)strtol(seconds, NULL, 10);
	return result;
}

bool oauth2_parse_bool(oauth2_log_t *log, const char *value, bool default_value)
{
	return value ? (strcasecmp(value, "true") == 0) : default_value;
}

oauth2_uint_t oauth2_parse_uint(oauth2_log_t *log, const char *int_value,
				oauth2_uint_t default_value)
{
	oauth2_uint_t result = default_value;
	if (int_value)
		result = (oauth2_uint_t)strtol(int_value, NULL, 10);
	return result;
}

/*
 * normalize a string for use as an HTTP Header Name.  Any invalid
 * characters (per http://tools.ietf.org/html/rfc2616#section-4.2 and
 * http://tools.ietf.org/html/rfc2616#section-2.2) are replaced with
 * a dash ('-') character.
 */
char *oauth2_normalize_header_name(const char *str)
{
	/* token = 1*<any CHAR except CTLs or separators>
	 * CTL = <any US-ASCII control character
	 *          (octets 0 - 31) and DEL (127)>
	 * separators = "(" | ")" | "<" | ">" | "@"
	 *              | "," | ";" | ":" | "\" | <">
	 *              | "/" | "[" | "]" | "?" | "="
	 *              | "{" | "}" | SP | HT */
	const char *separators = "()<>@,;:\\\"/[]?={} \t";

	char *ns = oauth2_strdup(str);
	size_t i;
	for (i = 0; i < strlen(ns); i++) {
		if (ns[i] < 32 || ns[i] == 127)
			ns[i] = '-';
		else if (strchr(separators, ns[i]) != NULL)
			ns[i] = '-';
	}
	return ns;
}

char *oauth_read_file(oauth2_log_t *log, const char *filename)
{
	char *rv = NULL;
	FILE *fp = NULL;
	long fsize = 0;
	size_t n = 0;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		oauth2_error(log, "could not read file: %s", filename);
		goto end;
	}

	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	rv = oauth2_mem_alloc(fsize + 1);
	n = fread(rv, 1, fsize, fp);
	if (n != fsize) {
		oauth2_error(log, "read only %ld bytes from file of %ld length",
			     n, fsize);
		oauth2_mem_free(rv);
		rv = NULL;
		goto end;
	}

	rv[fsize] = 0;

end:

	if (fp)
		fclose(fp);

	return rv;
}
