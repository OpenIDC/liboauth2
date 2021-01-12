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

#include <oauth2/jose.h>
#include <oauth2/mem.h>

#include "cfg_int.h"
#include "openidc_int.h"

#if defined(_WIN32) || defined(_WIN64)
	/* We are on Windows */
	#define strtok_r strtok_s
#endif

typedef struct oauth2_openidc_proto_state_t {
	json_t *state;
} oauth2_openidc_proto_state_t;

oauth2_openidc_proto_state_t *oauth2_openidc_proto_state_init(oauth2_log_t *log)
{
	oauth2_openidc_proto_state_t *p =
	    oauth2_mem_alloc(sizeof(oauth2_openidc_proto_state_t));
	p->state = json_object();
	return p;
}

oauth2_openidc_proto_state_t *
oauth2_openidc_proto_state_clone(oauth2_log_t *log,
				 const oauth2_openidc_proto_state_t *src)
{
	oauth2_openidc_proto_state_t *dst =
	    oauth2_openidc_proto_state_init(log);
	if (dst->state)
		json_decref(dst->state);
	dst->state = json_deep_copy(src->state);
	return dst;
}

void oauth2_openidc_proto_state_free(oauth2_log_t *log,
				     oauth2_openidc_proto_state_t *p)
{
	if (p->state)
		json_decref(p->state);
	oauth2_mem_free(p);
}

bool oauth2_openidc_proto_state_set(oauth2_log_t *log,
				    oauth2_openidc_proto_state_t *p,
				    const char *name, const char *value)
{
	json_object_set_new(p->state, name, json_string(value));
	return true;
}

bool oauth2_openidc_proto_state_set_int(oauth2_log_t *log,
					oauth2_openidc_proto_state_t *p,
					const char *name,
					const json_int_t value)
{
	json_object_set_new(p->state, name, json_integer(value));
	return true;
}

bool oauth2_openidc_proto_state_json_set(oauth2_log_t *log,
					 oauth2_openidc_proto_state_t *p,
					 json_t *json)
{
	if (p->state)
		json_decref(p->state);
	p->state = json;
	return true;
}

json_t *
oauth2_openidc_proto_state_json_get(const oauth2_openidc_proto_state_t *p)
{
	return p->state;
}

bool oauth2_openidc_proto_state_target_link_uri_get(
    oauth2_log_t *log, oauth2_openidc_proto_state_t *p, char **value)
{
	return oauth2_json_string_get(
	    log, oauth2_openidc_proto_state_json_get(p),
	    _OAUTH2_OPENIDC_PROTO_STATE_KEY_TARGET_LINK_URI, value, NULL);
}

bool oauth2_openidc_proto_state_pkce_get(oauth2_log_t *log,
					 oauth2_openidc_proto_state_t *p,
					 char **value)
{
	return oauth2_json_string_get(
	    log, oauth2_openidc_proto_state_json_get(p),
	    _OAUTH2_OPENIDC_PROTO_STATE_KEY_PKCE, value, NULL);
}

static oauth2_openidc_proto_state_t *_oauth2_openidc_proto_state_create(
    oauth2_log_t *log, oauth2_openidc_provider_t *provider,
    const char *target_link_uri, const char *pkce,
    const oauth2_http_request_t *request)
{
	oauth2_openidc_proto_state_t *p = oauth2_openidc_proto_state_init(log);
	oauth2_openidc_proto_state_set(
	    log, p, _OAUTH2_OPENIDC_PROTO_STATE_KEY_ISSUER,
	    oauth2_openidc_provider_issuer_get(log, provider));
	oauth2_openidc_proto_state_set(
	    log, p, _OAUTH2_OPENIDC_PROTO_STATE_KEY_TARGET_LINK_URI,
	    target_link_uri);
	oauth2_openidc_proto_state_set(
	    log, p, _OAUTH2_OPENIDC_PROTO_STATE_KEY_PKCE, pkce);
	oauth2_openidc_proto_state_set_int(
	    log, p, _OAUTH2_OPENIDC_PROTO_STATE_KEY_REQUEST_METHOD,
	    oauth2_http_request_method_get(log, request));
	oauth2_openidc_proto_state_set_int(
	    log, p, _OAUTH2_OPENIDC_PROTO_STATE_KEY_TIMESTAMP,
	    oauth2_time_now_sec());
	// TODO: response mode _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_MODE
	// TODO: response type _OAUTH2_OPENIDC_PROTO_STATE_KEY_RESPONSE_TYPE
	return p;
}

typedef struct oidc_state_cookies_t {
	char *name;
	oauth2_time_t timestamp;
	char *target_uri;
	struct oidc_state_cookies_t *next;
} oidc_state_cookies_t;

static bool _oauth2_openidc_cookie_clear(oauth2_log_t *log,
					 oauth2_http_response_t *response,
					 const char *name, const char *path,
					 const bool is_secure)
{
	return oauth2_http_response_cookie_set(
	    log, response, name, NULL, path, is_secure, OAUTH2_CFG_TIME_UNSET);
}

static int _oauth2_openidc_delete_oldest_state_cookies(
    oauth2_log_t *log, oauth2_http_response_t *response, const char *path,
    int number_of_valid_state_cookies, int max_number_of_state_cookies,
    oidc_state_cookies_t **first, const bool is_secure)
{
	oidc_state_cookies_t *cur = NULL, *prev = NULL, *prev_oldest = NULL,
			     *oldest = NULL;

	while (number_of_valid_state_cookies >= max_number_of_state_cookies) {

		oldest = *first;
		prev_oldest = NULL;
		prev = *first;
		cur = (*first)->next;

		while (cur) {
			if ((cur->timestamp < oldest->timestamp)) {
				oldest = cur;
				prev_oldest = prev;
			}
			prev = cur;
			cur = cur->next;
		}

		oauth2_warn(
		    log,
		    "deleting oldest state cookie: %s ; time until "
		    "expiry " OAUTH2_TIME_T_FORMAT " seconds [target_uri=%s]",
		    oldest->name, oldest->timestamp - oauth2_time_now_sec(),
		    oldest->target_uri);
		_oauth2_openidc_cookie_clear(log, response, oldest->name, path,
					     is_secure);
		if (prev_oldest)
			prev_oldest->next = oldest->next;
		else
			*first = (*first)->next;

		number_of_valid_state_cookies--;

		oauth2_mem_free(oldest->name);
		oauth2_mem_free(oldest->target_uri);
		oauth2_mem_free(oldest);
	}
	return number_of_valid_state_cookies;
}

static bool _oauth2_openidc_state_expired(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_openidc_proto_state_t *proto_state, oauth2_time_t *tsr)
{
	bool rc = true;
	oauth2_time_t now, exp;
	oauth2_time_t ts;

	now = oauth2_time_now_sec();

	ts = json_integer_value(
	    json_object_get(oauth2_openidc_proto_state_json_get(proto_state),
			    _OAUTH2_OPENIDC_PROTO_STATE_KEY_TIMESTAMP));

	exp = oauth2_cfg_openidc_state_cookie_timeout_get(log, cfg);
	if (now > ts + exp) {
		oauth2_error(log, "state expired: now: %d, then: %d, ttl: %d",
			     now, ts, exp);
		goto end;
	}

	rc = false;

end:

	if (tsr)
		*tsr = ts;

	return rc;
}

static bool _oauth2_openidc_get_state_from_cookie(
    oauth2_log_t *log, const char *value,
    oauth2_openidc_proto_state_t **proto_state)
{
	bool rc = false;
	json_t *json = NULL;

	if (oauth2_jose_jwt_decrypt(log, oauth2_crypto_passphrase_get(log),
				    value, &json) == false)
		goto end;

	*proto_state = oauth2_openidc_proto_state_init(log);
	oauth2_openidc_proto_state_json_set(log, *proto_state, json);

	rc = true;

end:

	return rc;
}

static oidc_state_cookies_t *
_oauth2_openidc_cookie_valid(oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
			     const oauth2_http_request_t *request,
			     oauth2_http_response_t *response, char *cookie,
			     const char *path)
{
	oidc_state_cookies_t *entry = NULL;
	oauth2_openidc_proto_state_t *proto_state = NULL;
	char *cookieStart = NULL, *cookieName = NULL, *cookieValue = NULL;
	oauth2_time_t ts;
	char *target_uri = NULL;

	cookieStart = cookie;
	while (cookie != NULL && *cookie != '=')
		cookie++;

	if (*cookie != '=')
		goto end;

	*cookie = '\0';
	cookie++;

	cookieName = oauth2_url_decode(log, cookieStart);
	cookieValue = oauth2_url_decode(log, cookie);

	if ((_oauth2_openidc_get_state_from_cookie(log, cookieValue,
						   &proto_state) == false) ||
	    (proto_state == NULL)) {
		oauth2_warn(
		    log,
		    "state cookie could not be retrieved/decoded, deleting: %s",
		    cookieName);
		_oauth2_openidc_cookie_clear(
		    log, response, cookieName, path,
		    oauth2_http_request_is_secure(log, request));
		goto end;
	}

	oauth2_openidc_proto_state_target_link_uri_get(log, proto_state,
						       &target_uri);

	if (_oauth2_openidc_state_expired(log, cfg, proto_state, &ts)) {
		oauth2_warn(log, "state (%s) has expired [target_uri=%s]",
			    cookieName, target_uri);
		_oauth2_openidc_cookie_clear(
		    log, response, cookieName, path,
		    oauth2_http_request_is_secure(log, request));
		goto end;
	}

	entry = oauth2_mem_alloc(sizeof(oidc_state_cookies_t));
	entry->name = oauth2_strdup(cookieName);
	entry->timestamp = ts;
	entry->target_uri = oauth2_strdup(target_uri);
	entry->next = NULL;

end:

	if (cookieName)
		oauth2_mem_free(cookieName);
	if (cookieValue)
		oauth2_mem_free(cookieValue);
	if (target_uri)
		oauth2_mem_free(target_uri);
	if (proto_state)
		oauth2_openidc_proto_state_free(log, proto_state);

	return entry;
}

static bool _oauth2_openidc_clean_expired_state_cookies(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, oauth2_http_response_t *response)
{
	bool rc = false;
	char *cookies = NULL, *save_ptr = NULL;
	oidc_state_cookies_t *first = NULL, *last = NULL, *entry = NULL;
	const char delim[2] = ";";
	int number_of_valid_state_cookies = 0;
	char *cookieStr = NULL;

	// TODO: session reference...?
	const char *path = oauth2_cfg_session_cookie_path_get(
	    log, oauth2_cfg_openidc_session_get(log, cfg));

	cookies =
	    oauth2_strdup(oauth2_http_request_header_cookie_get(log, request));
	if (cookies == NULL) {
		rc = true;
		goto end;
	}

	cookieStr = strtok_r(cookies, delim, &save_ptr);

	while (cookieStr != NULL) {

		while (*cookieStr == ' ')
			cookieStr++;

		if (strstr(cookieStr,
			   oauth2_cfg_openidc_state_cookie_name_prefix_get(
			       log, cfg)) != cookieStr)
			goto cont;

		entry = _oauth2_openidc_cookie_valid(log, cfg, request,
						     response, cookieStr, path);
		if (entry == NULL)
			goto cont;

		if (first == NULL) {
			first = entry;
			last = first;
		} else {
			last->next = entry;
			last = last->next;
		}

		number_of_valid_state_cookies++;

	cont:
		cookieStr = strtok_r(NULL, delim, &save_ptr);
	}

	if ((number_of_valid_state_cookies >=
	     oauth2_cfg_openidc_state_cookie_max_get(log, cfg)) &&
	    (oauth2_cfg_openidc_state_cookie_delete_oldest_get(log, cfg) ==
	     false)) {
		oauth2_debug(log,
			     "max number of state cookies has been reached");
		goto end;
	}

	_oauth2_openidc_delete_oldest_state_cookies(
	    log, response, path, number_of_valid_state_cookies,
	    oauth2_cfg_openidc_state_cookie_max_get(log, cfg), &first,
	    oauth2_http_request_is_secure(log, request));

	rc = true;

end:

	while (first) {
		entry = first;
		first = first->next;
		oauth2_mem_free(entry->name);
		oauth2_mem_free(entry->target_uri);
		oauth2_mem_free(entry);
	}

	if (cookies)
		oauth2_mem_free(cookies);

	return rc;
}

/*
 * state cookie handling
 */
bool _oauth2_openidc_state_cookie_set(oauth2_log_t *log,
				      const oauth2_cfg_openidc_t *cfg,
				      oauth2_openidc_provider_t *provider,
				      const oauth2_http_request_t *request,
				      oauth2_http_response_t *response,
				      const char *state, const char *pkce)
{
	bool rc = false;
	char *name = NULL, *value = NULL, *target_link_uri = NULL;
	oauth2_openidc_proto_state_t *proto_state = NULL;
	const char *path = NULL;

	name = oauth2_stradd(
	    name, oauth2_cfg_openidc_state_cookie_name_prefix_get(log, cfg),
	    state, NULL);
	if (name == NULL)
		goto end;

	if (_oauth2_openidc_clean_expired_state_cookies(log, cfg, request,
							response) == false)
		goto end;

	target_link_uri = oauth2_http_request_url_get(log, request);

	// TODO: add different state policy that keeps track in the
	// shared cache of outstanding parallel requests from the same
	// client (ip/user-agent) against a configurable maximum and
	// uses only a single shared cookie across those requests
	// (accepting consecutive responses, or take the last one)

	proto_state = _oauth2_openidc_proto_state_create(
	    log, provider, target_link_uri, pkce, request);

	if (oauth2_jose_jwt_encrypt(
		log, oauth2_crypto_passphrase_get(log),
		oauth2_openidc_proto_state_json_get(proto_state),
		&value) == false)
		goto end;

	path = oauth2_cfg_session_cookie_path_get(
	    log, oauth2_cfg_openidc_session_get(log, cfg));

	rc = oauth2_http_response_cookie_set(
	    log, response, name, value, path,
	    oauth2_http_request_is_secure(log, request),
	    oauth2_cfg_openidc_state_cookie_timeout_get(log, cfg));

end:

	if (proto_state)
		oauth2_openidc_proto_state_free(log, proto_state);
	if (name)
		oauth2_mem_free(name);
	if (value)
		oauth2_mem_free(value);
	if (target_link_uri)
		oauth2_mem_free(target_link_uri);

	return rc;
}

bool _oauth2_openidc_state_cookie_get(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    oauth2_http_request_t *request, oauth2_http_response_t *response,
    const char *state, oauth2_openidc_proto_state_t **proto_state)
{
	bool rc = false;
	char *name = NULL, *value = NULL;
	const char *path = NULL;

	name = oauth2_stradd(
	    name, oauth2_cfg_openidc_state_cookie_name_prefix_get(log, cfg),
	    state, NULL);
	if (name == NULL)
		goto end;

	value = oauth2_http_request_cookie_get(log, request, name, true);
	if (value == NULL) {
		oauth2_warn(log, "no state cookie found");
		goto end;
	}

	path = oauth2_cfg_session_cookie_path_get(
	    log, oauth2_cfg_openidc_session_get(log, cfg));

	rc = _oauth2_openidc_cookie_clear(
	    log, response, name, path,
	    oauth2_http_request_is_secure(log, request));
	if (rc == false)
		goto end;

	rc = _oauth2_openidc_get_state_from_cookie(log, value, proto_state);

end:

	if (name)
		oauth2_mem_free(name);
	if (value)
		oauth2_mem_free(value);

	return rc;
}

bool _oauth2_openidc_state_validate(oauth2_log_t *log,
				    const oauth2_cfg_openidc_t *cfg,
				    oauth2_http_request_t *request,
				    oauth2_openidc_proto_state_t *proto_state,
				    oauth2_openidc_provider_t **provider)
{
	bool rc = false;
	const char *iss = NULL;

	iss = json_string_value(
	    json_object_get(oauth2_openidc_proto_state_json_get(proto_state),
			    _OAUTH2_OPENIDC_PROTO_STATE_KEY_ISSUER));
	if (iss == NULL) {
		oauth2_error(log, "no issuer (key=%s) found in state",
			     _OAUTH2_OPENIDC_PROTO_STATE_KEY_ISSUER);
		goto end;
	}

	if (_oauth2_openidc_provider_resolve(log, cfg, request, iss,
					     provider) == false) {
		oauth2_error(log,
			     "_oauth2_openidc_provider_resolve returned false");
		goto end;
	}

	if (_oauth2_openidc_state_expired(log, cfg, proto_state, NULL))
		goto end;

	rc = true;

end:

	return rc;
}
