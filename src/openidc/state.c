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

	target_link_uri = oauth2_http_request_url_get(log, request);

	// TODO: add different state policy that keeps track in the shared cache
	// of outstanding parallel requests from the same client (ip/user-agent)
	// against a configurable maximum and uses only a single shared cookie
	// across those requests (accepting consecutive responses, or take the
	// last one)

	proto_state = _oauth2_openidc_proto_state_create(
	    log, provider, target_link_uri, pkce, request);

	if (oauth2_jose_jwt_encrypt(
		log, oauth2_crypto_passphrase_get(log),
		oauth2_openidc_proto_state_json_get(proto_state),
		&value) == false)
		goto end;

	path = oauth2_cfg_session_cookie_path_get(
	    log, oauth2_cfg_openidc_session_get(log, cfg));

	rc = oauth2_http_response_cookie_set(log, response, name, value, path);

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
	json_t *json = NULL;
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

	rc = oauth2_http_response_cookie_set(log, response, name, NULL, path);

	if (oauth2_jose_jwt_decrypt(log, oauth2_crypto_passphrase_get(log),
				    value, &json) == false)
		goto end;

	*proto_state = oauth2_openidc_proto_state_init(log);
	oauth2_openidc_proto_state_json_set(log, *proto_state, json);

end:

	if (name)
		oauth2_mem_free(name);
	if (value)
		oauth2_mem_free(value);

	return rc;
}

#define OAUTH2_OPENIDC_STATE_TIMEOUT_DEFAULT 300

bool _oauth2_openidc_state_validate(oauth2_log_t *log,
				    const oauth2_cfg_openidc_t *cfg,
				    oauth2_http_request_t *request,
				    oauth2_openidc_proto_state_t *proto_state,
				    oauth2_openidc_provider_t **provider)
{
	bool rc = false;
	const char *iss = NULL;
	json_int_t ts;
	oauth2_uint_t now;

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

	now = oauth2_time_now_sec();
	ts = json_integer_value(
	    json_object_get(oauth2_openidc_proto_state_json_get(proto_state),
			    _OAUTH2_OPENIDC_PROTO_STATE_KEY_TIMESTAMP));
	// TODO: use a configurable timeout
	if (now > ts + OAUTH2_OPENIDC_STATE_TIMEOUT_DEFAULT) {
		oauth2_error(log, "state expired: now: %d, then: %d, ttl: %d",
			     now, ts, OAUTH2_OPENIDC_STATE_TIMEOUT_DEFAULT);
		goto end;
	}

	rc = true;

end:

	return rc;
}
