#ifndef _OAUTH2_UTIL_H
#define _OAUTH2_UTIL_H

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

/**
 * @file util.h
 * @brief Basic types, the object declaration macros, name/value lists
 *        and generic helpers.
 *
 * Everything else in the library builds on what is declared here: the
 * scalar types and their printf formats, the OAUTH2_TYPE_DECLARE
 * family of macros that generate the init/clone/free functions and
 * the member accessors of every public object type, the
 * oauth2_nv_list_t name/value list that carries options, parameters
 * and headers, and helpers for string handling, encoding, JSON,
 * random data, time and option parsing. Memory returned by any of
 * these functions is allocated with oauth2_mem_alloc() (mem.h) and
 * must be released with oauth2_mem_free().
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "oauth2/log.h"
#include <jansson.h>

/**
 * @name Preprocessor helpers
 * @{
 */
/** @brief Turn a token into a string literal, without expanding it. */
#define OAUTH2_STRINGIFY(x) #x
/** @brief Turn a macro's expansion into a string literal. */
#define OAUTH2_TOSTRING(x) OAUTH2_STRINGIFY(x)
/** @} */

/**
 * @name Basic types
 * The scalar types used throughout the API and their printf formats.
 * @{
 */
/**
 * @brief A tri-state boolean setting: 0 (off), 1 (on) or
 *        OAUTH2_CFG_FLAG_UNSET (cfg.h) when not configured.
 */
typedef char oauth2_flag_t;
/** @brief An unsigned integer setting, e.g. a count, size or status. */
typedef unsigned int oauth2_uint_t;
/**
 * @brief A point in time as seconds since the epoch, or a duration in
 *        seconds; 64-bit on every platform.
 */
typedef uint64_t oauth2_time_t;

/** @brief printf conversion specifier for an oauth2_uint_t. */
#define OAUTH2_UINT_FORMAT "%u"
/** @brief printf conversion specifier for an oauth2_time_t. */
#ifdef _WIN32
// LLP64: long is 32 bits there, so a 64-bit oauth2_time_t needs long long
#define OAUTH2_TIME_T_FORMAT "%llu"
#else
#define OAUTH2_TIME_T_FORMAT "%lu"
#endif

/** @brief Milliseconds in a second. */
#define OAUTH2_MSEC_PER_SEC 1000
/** @brief Microseconds in a millisecond. */
#define OAUTH2_USEC_PER_MSEC 1000
/** @} */

/**
 * @name Object type declaration macros
 * The public object types are declared with these macros rather than
 * by hand: OAUTH2_TYPE_DECLARE(module, object) names the opaque type
 * oauth2_<module>_<object>_t and declares its lifecycle functions,
 * and the OAUTH2_TYPE_DECLARE_MEMBER_* macros declare typed accessors
 * for the individual members of such an object. The
 * OAUTH2_MEMBER_LIST_DECLARE_* macros declare accessors for a member
 * that is itself an oauth2_nv_list_t (e.g. the headers of an HTTP
 * request), and the OAUTH2_LIST_DECLARE_* macros declare the
 * name/value interface of an object that is a list itself.
 *
 * The implementations live with the module that defines the type;
 * every generated function takes an oauth2_log_t as its first
 * argument, as the rest of the API does.
 * @{
 */

/**
 * @brief Declare an object type and its lifecycle functions.
 *
 * Generates the opaque typedef oauth2_<module>_<object>_t and three
 * lifecycle functions carrying the same prefix:
 * - init(log): allocate a new, zeroed object with its defaults
 *   applied; NULL on allocation failure
 * - clone(log, src): a deep copy of src, to be released like src
 *   itself; NULL when src is NULL or on failure
 * - free(log, obj): release the object and everything it owns; a
 *   NULL obj is ignored
 */
#define OAUTH2_TYPE_DECLARE(module, object)                                    \
	typedef struct oauth2_##module##_##object##_t                          \
	    oauth2_##module##_##object##_t;                                    \
	oauth2_##module##_##object##_t *oauth2_##module##_##object##_init(     \
	    oauth2_log_t *);                                                   \
	oauth2_##module##_##object##_t *oauth2_##module##_##object##_clone(    \
	    oauth2_log_t *, const oauth2_##module##_##object##_t *);           \
	void oauth2_##module##_##object##_free(                                \
	    oauth2_log_t *, oauth2_##module##_##object##_t *);

/**
 * @brief Declare a setter oauth2_<module>_<object>_<member>_set(log,
 *        obj, value) for a member of an object type.
 *
 * A string (char *) member is set to a copy of the value, releasing
 * the previously set string; NULL is rejected. Scalar members (bool,
 * oauth2_uint_t, oauth2_time_t, ...) are assigned; pointer members
 * store the pointer as-is, so the caller keeps ownership of the
 * pointed-to object. Returns true on success, false when obj is NULL
 * or the copy failed.
 */
#define OAUTH2_TYPE_DECLARE_MEMBER_SET(module, object, member, type)           \
	bool oauth2_##module##_##object##_##member##_set(                      \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const type);

/**
 * @brief Declare a getter oauth2_<module>_<object>_<member>_get(log,
 *        obj) for a member of an object type.
 *
 * Returns the member's value as stored: a borrowed pointer for string
 * and pointer members, owned by the object and valid until the object
 * is modified or freed.
 */
#define OAUTH2_TYPE_DECLARE_MEMBER_GET(module, object, member, type)           \
	type oauth2_##module##_##object##_##member##_get(                      \
	    oauth2_log_t *, const oauth2_##module##_##object##_t *);

/** @brief Declare both the setter and the getter for a member. */
#define OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(module, object, member, type)       \
	OAUTH2_TYPE_DECLARE_MEMBER_SET(module, object, member, type)           \
	OAUTH2_TYPE_DECLARE_MEMBER_GET(module, object, member, type)

/**
 * @brief Declare oauth2_<module>_<object>_<member>_set(log, obj, name,
 *        value) for an oauth2_nv_list_t member, with the semantics of
 *        oauth2_nv_list_set().
 */
#define OAUTH2_MEMBER_LIST_DECLARE_SET(module, object, member)                 \
	bool oauth2_##module##_##object##_##member##_set(                      \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const char *,    \
	    const char *);

/**
 * @brief Declare oauth2_<module>_<object>_<member>_unset(log, obj,
 *        name) for an oauth2_nv_list_t member, with the semantics of
 *        oauth2_nv_list_unset().
 */
#define OAUTH2_MEMBER_LIST_DECLARE_UNSET(module, object, member)               \
	bool oauth2_##module##_##object##_##member##_unset(                    \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const char *);

/**
 * @brief Declare oauth2_<module>_<object>_<member>_add(log, obj, name,
 *        value) for an oauth2_nv_list_t member, with the semantics of
 *        oauth2_nv_list_add().
 */
#define OAUTH2_MEMBER_LIST_DECLARE_ADD(module, object, member)                 \
	bool oauth2_##module##_##object##_##member##_add(                      \
	    oauth2_log_t *, oauth2_##module##_##object##_t *, const char *,    \
	    const char *);

/**
 * @brief Declare oauth2_<module>_<object>_<member>_get(log, obj, name)
 *        for an oauth2_nv_list_t member, with the semantics of
 *        oauth2_nv_list_get().
 */
#define OAUTH2_MEMBER_LIST_DECLARE_GET(module, object, member)                 \
	const char *oauth2_##module##_##object##_##member##_get(               \
	    oauth2_log_t *, const oauth2_##module##_##object##_t *,            \
	    const char *);

/**
 * @brief Declare the set, unset, add and get accessors for an
 *        oauth2_nv_list_t member.
 */
#define OAUTH2_MEMBER_LIST_DECLARE_SET_UNSET_ADD_GET(module, object, member)   \
	OAUTH2_MEMBER_LIST_DECLARE_SET(module, object, member)                 \
	OAUTH2_MEMBER_LIST_DECLARE_UNSET(module, object, member)               \
	OAUTH2_MEMBER_LIST_DECLARE_ADD(module, object, member)                 \
	OAUTH2_MEMBER_LIST_DECLARE_GET(module, object, member)

/**
 * @brief Declare oauth2_<module>_<type>_set(log, list, name, value)
 *        for a list type; see oauth2_nv_list_set().
 */
#define OAUTH2_LIST_DECLARE_SET(module, type)                                  \
	bool oauth2_##module##_##type##_set(oauth2_log_t *,                    \
					    oauth2_##module##_##type##_t *,    \
					    const char *, const char *);

/**
 * @brief Declare oauth2_<module>_<type>_unset(log, list, name) for a
 *        list type; see oauth2_nv_list_unset().
 */
#define OAUTH2_LIST_DECLARE_UNSET(module, type)                                \
	bool oauth2_##module##_##type##_unset(                                 \
	    oauth2_log_t *, oauth2_##module##_##type##_t *, const char *);

/**
 * @brief Declare oauth2_<module>_<type>_add(log, list, name, value)
 *        for a list type; see oauth2_nv_list_add().
 */
#define OAUTH2_LIST_DECLARE_ADD(module, type)                                  \
	bool oauth2_##module##_##type##_add(oauth2_log_t *,                    \
					    oauth2_##module##_##type##_t *,    \
					    const char *, const char *);

/**
 * @brief Declare oauth2_<module>_<type>_get(log, list, name) for a
 *        list type; see oauth2_nv_list_get().
 */
#define OAUTH2_LIST_DECLARE_GET(module, type)                                  \
	const char *oauth2_##module##_##type##_get(                            \
	    oauth2_log_t *, const oauth2_##module##_##type##_t *,              \
	    const char *);

/**
 * @brief Declare the set, unset, add and get functions of a list
 *        type.
 */
#define OAUTH2_LIST_DECLARE_SET_UNSET_ADD_GET(module, type)                    \
	OAUTH2_LIST_DECLARE_SET(module, type)                                  \
	OAUTH2_LIST_DECLARE_UNSET(module, type)                                \
	OAUTH2_LIST_DECLARE_ADD(module, type)                                  \
	OAUTH2_LIST_DECLARE_GET(module, type)
/** @} */

/**
 * @name Name/value lists
 * oauth2_nv_list_t is an ordered list of name/value string pairs that
 * may hold the same name more than once; it carries configuration
 * options, request parameters, headers and cookies throughout the
 * API. Names are matched case-sensitively unless case_sensitive is
 * set to false; the list copies the names and values it is given and
 * owns them. Create a list with oauth2_nv_list_init(), copy it with
 * oauth2_nv_list_clone() and release it with oauth2_nv_list_free().
 *
 * The set, unset, add and get functions declared here:
 * - oauth2_nv_list_set(log, list, name, value): replace the value of
 *   the first entry with that name, or append a new entry when there
 *   is none; a NULL value is stored as such
 * - oauth2_nv_list_unset(log, list, name): remove the first entry
 *   with that name; succeeds when there is none
 * - oauth2_nv_list_add(log, list, name, value): append an entry,
 *   even when the name is already present (e.g. repeated query
 *   parameters or headers)
 * - oauth2_nv_list_get(log, list, name): the value of the first entry
 *   with that name, borrowed from the list, or NULL when absent or
 *   stored as NULL
 *
 * All of them return false, or NULL, when the list or name is NULL.
 * @{
 */
OAUTH2_TYPE_DECLARE(nv, list)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(nv, list, case_sensitive, bool)
OAUTH2_LIST_DECLARE_SET_UNSET_ADD_GET(nv, list)

/**
 * @brief Callback invoked by oauth2_nv_list_loop() for each entry.
 *
 * @param log   the log handle to use
 * @param rec   the caller's context passed to oauth2_nv_list_loop()
 * @param key   the entry's name, borrowed from the list
 * @param value the entry's value, borrowed from the list; may be NULL
 * @return true to continue with the next entry, false to stop the
 *         iteration
 */
typedef bool(oauth2_nv_list_loop_cb_t)(oauth2_log_t *log, void *rec,
				       const char *key, const char *value);

/**
 * @brief Iterate over the entries of a list, in insertion order,
 *        until the callback returns false.
 */
void oauth2_nv_list_loop(oauth2_log_t *log, const oauth2_nv_list_t *list,
			 oauth2_nv_list_loop_cb_t *callback, void *rec);

/**
 * @brief Render a list for logging purposes.
 *
 * @return a newly allocated string in the form "[ name=value ... ]",
 *         to be released with oauth2_mem_free()
 */
char *oauth2_nv_list2s(oauth2_log_t *log, const oauth2_nv_list_t *list);

/**
 * @brief Append copies of all entries of source to target.
 *
 * Entries are added, not set, so names already present in target are
 * repeated rather than overwritten; a NULL source is ignored.
 */
void oauth2_nv_list_merge_into(oauth2_log_t *log,
			       const oauth2_nv_list_t *source,
			       oauth2_nv_list_t *target);
/** @} */

/**
 * @name Library initialization
 * @{
 */

/**
 * @brief Initialize the library.
 *
 * Call once, before any other function, from the main thread: this
 * initializes OpenSSL and libcurl (curl_global_init) and creates the
 * global log handle with oauth2_log_init() (log.h). To use a custom
 * allocator, call oauth2_mem_set_alloc_funcs() (mem.h) before this.
 *
 * @param level the log level of the initial sink
 * @param sink  the log sink to send messages to, e.g.
 *              oauth2_log_sink_stderr, or NULL for no output
 * @return the log handle to pass to the other functions and to
 *         oauth2_shutdown() when done
 */
oauth2_log_t *oauth2_init(oauth2_log_level_t level, oauth2_log_sink_t *sink);

/**
 * @brief Shut the library down.
 *
 * Releases the global cache and session state and the libcurl and
 * OpenSSL resources, and frees the log handle returned by
 * oauth2_init(); no library function may be called afterwards.
 */
void oauth2_shutdown(oauth2_log_t *);
/** @} */

/**
 * @name String helpers
 * All strings returned by these functions are newly allocated and to
 * be released with oauth2_mem_free().
 * @{
 */

/**
 * @brief snprintf() that tolerates a NULL destination or format.
 *
 * @return the value snprintf() returns, or 0 when dst or fmt is NULL
 */
int oauth2_snprintf(char *dst, size_t len, const char *fmt, ...);

/** @brief Copy a string; NULL for a NULL src or on allocation failure. */
char *oauth2_strdup(const char *src);

/**
 * @brief Copy the first len bytes of a string, NUL-terminating the
 *        result; NULL for a NULL src or on allocation failure.
 */
char *oauth2_strndup(const char *src, size_t len);

/**
 * @brief Concatenate strings.
 *
 * @param src  the string to append to, which this function takes
 *             ownership of and releases; NULL starts from an empty
 *             string
 * @param add1 the first string to append, or NULL for none
 * @param add2 the second string to append, or NULL for none
 * @param add3 the third string to append, or NULL for none
 * @return a new string holding the concatenation, replacing src, or
 *         NULL on allocation failure
 */
char *oauth2_stradd(char *src, const char *add1, const char *add2,
		    const char *add3);

/**
 * @brief Concatenate strings and the decimal representation of an
 *        integer, with the ownership semantics of oauth2_stradd().
 */
char *oauth2_intadd(char *src, const char *add1, const char *add2, int i);

/**
 * @brief Split off the next word of a string.
 *
 * @param line the position to read from; advanced past the word and
 *             past any run of stop characters that follows it
 * @param stop the separator character
 * @return a copy of the characters up to the separator or the end of
 *         the string, possibly empty
 */
char *oauth2_getword(const char **line, char stop);
/** @} */

/**
 * @name Encoding and escaping
 * @{
 */

/**
 * @brief Base64url-encode (RFC 4648 section 5, without padding) a
 *        byte buffer.
 *
 * @param log     the log handle to use
 * @param src     the bytes to encode
 * @param src_len the number of bytes to encode
 * @param dst     set to the NUL-terminated encoded string, to be
 *                released with oauth2_mem_free(); NULL on error
 * @return the length of the encoded string, 0 on error
 */
size_t oauth2_base64url_encode(oauth2_log_t *log, const uint8_t *src,
			       const size_t src_len, char **dst);

/**
 * @brief Decode a base64url-encoded string.
 *
 * @param log     the log handle to use
 * @param src     the string to decode
 * @param dst     set to the decoded bytes, to be released with
 *                oauth2_mem_free(); NULL on error
 * @param dst_len set to the number of decoded bytes
 * @return true on success, false on error
 */
bool oauth2_base64url_decode(oauth2_log_t *log, const char *src, uint8_t **dst,
			     size_t *dst_len);

/** @brief As oauth2_base64url_encode(), for standard padded base64. */
size_t oauth2_base64_encode(oauth2_log_t *log, const uint8_t *src,
			    const size_t src_len, char **dst);

/** @brief As oauth2_base64url_decode(), for standard padded base64. */
bool oauth2_base64_decode(oauth2_log_t *log, const char *src, uint8_t **dst,
			  size_t *dst_len);

/**
 * @brief Percent-encode a string for use in a URL or form body.
 *
 * @return the encoded string, to be released with oauth2_mem_free();
 *         NULL for a NULL str or on error
 */
char *oauth2_url_encode(oauth2_log_t *log, const char *str);

/**
 * @brief Decode a percent-encoded string, turning "+" into a space
 *        as in form-encoded data.
 *
 * @return the decoded string, to be released with oauth2_mem_free();
 *         NULL for a NULL str or on error
 */
char *oauth2_url_decode(oauth2_log_t *log, const char *str);

/**
 * @brief Escape the HTML special characters &, ', ", < and > in a
 *        string.
 *
 * @return the escaped string, to be released with oauth2_mem_free();
 *         NULL for a NULL src
 */
char *oauth2_html_escape(oauth2_log_t *log, const char *src);

/**
 * @brief Parse a form-encoded (application/x-www-form-urlencoded)
 *        string, e.g. a query string or POST body, into a list.
 *
 * @param log    the log handle to use
 * @param data   the "name=value&name=value" string to parse; a NULL
 *               data succeeds without touching params
 * @param params set to a newly allocated list of the decoded
 *               parameters, in order and with repeated names kept,
 *               to be released with oauth2_nv_list_free()
 * @return true on success, false on error
 */
bool oauth2_parse_form_encoded_params(oauth2_log_t *log, const char *data,
				      oauth2_nv_list_t **params);
/** @} */

/**
 * @name JSON helpers
 * Conveniences on top of jansson for the JSON documents exchanged in
 * the protocols: parsing and typed member lookups with defaults.
 * @{
 */

/**
 * @brief Parse a JSON object and check that it is not an OAuth 2.x
 *        error response.
 *
 * As oauth2_json_decode_object(), but a document containing an
 * "error" member (RFC 6749 section 5.2) is logged, together with its
 * "error_description", and rejected.
 *
 * @param log  the log handle to use
 * @param str  the JSON text to parse
 * @param json set to the parsed object, to be released with
 *             json_decref(); NULL on failure
 * @return true on success, false when the text does not parse to an
 *         object or contains an "error" member
 */
bool oauth2_json_decode_check_error(oauth2_log_t *log, const char *str,
				    json_t **json);

/**
 * @brief Parse a JSON text that must be a JSON object.
 *
 * @param log     the log handle to use
 * @param payload the JSON text to parse
 * @param json    set to the parsed object, to be released with
 *                json_decref(); NULL on failure
 * @return true on success, false when the text does not parse or is
 *         not an object
 */
bool oauth2_json_decode_object(oauth2_log_t *log, const char *payload,
			       json_t **json);

/**
 * @brief Get an object-valued member of a JSON object.
 *
 * @param log   the log handle to use
 * @param json  the object to look in
 * @param name  the member name
 * @param value set to a new reference to the member, to be released
 *              with json_decref(); left untouched when the member is
 *              absent or null
 * @return true when the member is an object or null, false when it
 *         is absent, of another type or an argument is NULL
 */
bool oauth2_json_object_get(oauth2_log_t *log, const json_t *json,
			    const char *name, json_t **value);

/**
 * @brief Get a string-valued member of a JSON object.
 *
 * @param log           the log handle to use
 * @param json          the object to look in
 * @param name          the member name
 * @param value         set to a copy of the member's string, or of
 *                      default_value when the member is absent and a
 *                      default was given, to be released with
 *                      oauth2_mem_free(); left untouched for a null
 *                      member or when there is no default
 * @param default_value the value to return when the member is
 *                      absent, or NULL for none
 * @return true when the member is a string, null or absent, false
 *         when it is of another type or an argument is NULL
 */
bool oauth2_json_string_get(oauth2_log_t *log, const json_t *json,
			    const char *name, char **value,
			    const char *default_value);

/**
 * @brief Get a number-valued member of a JSON object.
 *
 * @param log           the log handle to use
 * @param json          the object to look in
 * @param name          the member name
 * @param number        set to the member's integer value, or to
 *                      default_value when the member is absent or
 *                      null
 * @param default_value the value to return when the member is absent
 * @return true when the member is a number, null or absent, false
 *         when it is of another type or an argument is NULL
 */
bool oauth2_json_number_get(oauth2_log_t *log, const json_t *json,
			    const char *name, json_int_t *number,
			    const json_int_t default_value);
/** @} */

/**
 * @name Random data, time and option parsing
 * @{
 */

/**
 * @brief Generate a random string, e.g. for a nonce, state value or
 *        cookie name.
 *
 * @param log the log handle to use
 * @param len the number of characters to generate
 * @return a string of len lowercase hexadecimal characters drawn from
 *         the OpenSSL random generator, to be released with
 *         oauth2_mem_free(); NULL when len is 0 or on error
 */
char *oauth2_rand_str(oauth2_log_t *log, size_t len);

/** @brief The current time in seconds since the epoch. */
oauth2_time_t oauth2_time_now_sec();

/**
 * @brief Parse a decimal number of seconds.
 *
 * @param log           the log handle to use
 * @param seconds       the string to parse, or NULL
 * @param default_value the value to return for a NULL seconds
 * @return the parsed value; 0 (as strtol() yields) for a string that
 *         is not a number
 */
oauth2_time_t oauth2_parse_time_sec(oauth2_log_t *log, const char *seconds,
				    oauth2_time_t default_value);

/**
 * @brief Parse a boolean option.
 *
 * @param log           the log handle to use
 * @param value         the string to parse, or NULL
 * @param default_value the value to return for a NULL value
 * @return true when value equals "true", case-insensitively, false
 *         for any other string
 */
bool oauth2_parse_bool(oauth2_log_t *log, const char *value,
		       bool default_value);

/**
 * @brief Parse a decimal unsigned integer.
 *
 * @param log           the log handle to use
 * @param int_value     the string to parse, or NULL
 * @param default_value the value to return for a NULL int_value
 * @return the parsed value; 0 (as strtol() yields) for a string that
 *         is not a number
 */
oauth2_uint_t oauth2_parse_uint(oauth2_log_t *log, const char *int_value,
				oauth2_uint_t default_value);
/** @} */

/**
 * @name Header name and value helpers
 * @{
 */

/**
 * @brief Compare two strings as environment variable names.
 *
 * Both strings are compared after normalizing each character the way
 * a header name is turned into an environment variable name: letters
 * and digits uppercased, anything else mapped to an underscore, so
 * that e.g. "Content-Type" and "CONTENT_TYPE" compare equal.
 *
 * @param a   the first string
 * @param b   the second string
 * @param len the number of characters to compare, or a negative value
 *            to compare the whole strings
 * @return 0 when equal, negative when a sorts before b, positive
 *         otherwise, as strcmp()
 */
int oauth2_strnenvcmp(const char *a, const char *b, int len);

/**
 * @brief Serialize a JSON value.
 *
 * @param log   the log handle to use
 * @param json  the value to serialize
 * @param flags jansson json_dumps() flags, e.g. JSON_COMPACT or
 *              JSON_ENCODE_ANY for a value that is not an object or
 *              array
 * @return the JSON text, to be released with oauth2_mem_free(); NULL
 *         when serialization fails
 */
char *oauth2_json_encode(oauth2_log_t *log, json_t *json, size_t flags);

/**
 * @brief Make a string usable as an HTTP header name.
 *
 * Replaces every character that is not allowed in a header field
 * name (control characters and the separators of RFC 2616 section
 * 2.2, including space) with a dash.
 *
 * @return the normalized name, to be released with oauth2_mem_free()
 */
char *oauth2_normalize_header_name(const char *str);

/**
 * @brief Convert a UTF-8 string to ISO-8859-1, for use as an HTTP
 *        header value.
 *
 * Code points above U+00FF, which have no Latin-1 representation, are
 * replaced with a question mark.
 *
 * @return the converted string, to be released with oauth2_mem_free();
 *         NULL for a NULL str
 */
char *oauth2_utf8_to_latin1(const char *str);
/** @} */

/**
 * @brief Read a whole file into memory.
 *
 * @param log      the log handle to use
 * @param filename the path of the file to read
 * @return the file contents as a NUL-terminated string, to be released
 *         with oauth2_mem_free(); NULL, having logged the reason, when
 *         the file cannot be read
 */
char *oauth_read_file(oauth2_log_t *log, const char *filename);

#endif /* _OAUTH2_UTIL_H */
