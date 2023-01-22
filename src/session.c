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

#include "oauth2/session.h"
#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include "cfg_int.h"
#include "util_int.h"

typedef struct oauth2_session_rec_t {
	char *id;
	oauth2_time_t start;
	oauth2_time_t expiry;
	char *user;
	char *id_token;
	json_t *id_token_claims;
	json_t *userinfo_claims;
} oauth2_session_rec_t;

oauth2_session_rec_t *oauth2_session_rec_init(oauth2_log_t *log)
{
	oauth2_session_rec_t *s = (oauth2_session_rec_t *)oauth2_mem_alloc(
	    sizeof(oauth2_session_rec_t));
	s->id = NULL;
	s->user = NULL;
	s->id_token = NULL;
	s->id_token_claims = NULL;
	s->userinfo_claims = NULL;
	s->expiry = 0;
	s->start = oauth2_time_now_sec();
	return s;
}

void oauth2_session_rec_free(oauth2_log_t *log, oauth2_session_rec_t *s)
{
	if (s->user)
		oauth2_mem_free(s->user);
	if (s->id_token)
		oauth2_mem_free(s->id_token);
	if (s->id_token_claims)
		json_decref(s->id_token_claims);
	if (s->userinfo_claims)
		json_decref(s->userinfo_claims);
	if (s->id)
		oauth2_mem_free(s->id);
	if (s)
		oauth2_mem_free(s);
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(session, rec, id, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(session, rec, user, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(session, rec, id_token, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(session, rec, start, oauth2_time_t, time)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(session, rec, expiry, oauth2_time_t, time)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_GET(session, rec, id_token_claims, json_t *)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_GET(session, rec, userinfo_claims, json_t *)

static bool _oauth2_session_rec_json_object_set(oauth2_log_t *log,
						oauth2_session_rec_t *session,
						const char *name, json_t *json,
						json_t **session_ptr)
{
	bool rc = false;
	char *s_json = NULL;

	if (json == NULL) {
		rc = true;
		goto end;
	}

	s_json = oauth2_json_encode(log, json, 0);
	oauth2_debug(log, "%s=%s", name, s_json);
	*session_ptr = json_incref(json);

	rc = true;

end:

	if (s_json)
		oauth2_mem_free(s_json);

	return rc;
}

bool oauth2_session_rec_id_token_claims_set(oauth2_log_t *log,
					    oauth2_session_rec_t *session,
					    json_t *id_token)
{
	return _oauth2_session_rec_json_object_set(
	    log, session, "id_token", id_token, &session->id_token_claims);
}

bool oauth2_session_rec_userinfo_claims_set(oauth2_log_t *log,
					    oauth2_session_rec_t *session,
					    json_t *userinfo_claims)
{
	return _oauth2_session_rec_json_object_set(log, session, "userinfo",
						   userinfo_claims,
						   &session->userinfo_claims);
}

#define OAUTH_SESSION_KEY_ID "id"
#define OAUTH_SESSION_KEY_USER "u"
#define OAUTH_SESSION_KEY_ID_TOKEN "i"
#define OAUTH_SESSION_KEY_ID_TOKEN_CLAIMS "ic"
#define OAUTH_SESSION_KEY_USERINFO_CLAIMS "uc"
#define OAUTH_SESSION_KEY_START "s"
#define OAUTH_SESSION_KEY_EXPIRY "e"

bool oauth2_session_load_cookie(oauth2_log_t *log,
				const oauth2_cfg_session_t *cfg,
				oauth2_http_request_t *request, json_t **json)
{
	bool rc = false;
	const char *name = NULL;
	char *value = NULL;

	name = oauth2_cfg_session_cookie_name_get(log, cfg);

	value = oauth2_http_request_cookie_get(log, request, name, true);
	if (value == NULL) {
		oauth2_debug(log, "no session cookie found");
		rc = true;
		goto end;
	}

	rc = oauth2_jose_jwt_decrypt(log, oauth2_crypto_passphrase_get(log),
				     value, json);

end:

	if (value)
		oauth2_mem_free(value);

	return rc;
}

bool oauth2_session_save_cookie(oauth2_log_t *log,
				const oauth2_cfg_session_t *cfg,
				const oauth2_http_request_t *request,
				oauth2_http_response_t *response, json_t *json)
{
	bool rc = false;
	const char *name = NULL, *path = NULL;
	;
	char *value = NULL;

	if (oauth2_jose_jwt_encrypt(log, oauth2_crypto_passphrase_get(log),
				    json, &value) == false)
		goto end;

	name = oauth2_cfg_session_cookie_name_get(log, cfg);
	path = oauth2_cfg_session_cookie_path_get(log, cfg);

	rc = oauth2_http_response_cookie_set(
	    log, response, name, value, path,
	    oauth2_http_request_is_secure(log, request), OAUTH2_CFG_TIME_UNSET);

end:

	if (value)
		oauth2_mem_free(value);

	return rc;
}

bool oauth2_session_load_cache(oauth2_log_t *log,
			       const oauth2_cfg_session_t *cfg,
			       oauth2_http_request_t *request, json_t **json)
{
	bool rc = false;
	const char *name = NULL;
	char *key = NULL, *value = NULL;

	name = oauth2_cfg_session_cookie_name_get(log, cfg);

	key = oauth2_http_request_cookie_get(log, request, name, true);
	if (key == NULL) {
		oauth2_debug(log, "no session cookie found");
		rc = true;
		goto end;
	}

	if (oauth2_cache_get(log, cfg->cache, key, &value) == false)
		goto end;

	if (value == NULL) {
		oauth2_debug(log, "no session found in cache");
		rc = true;
		goto end;
	}

	if (oauth2_json_decode_object(log, value, json) == false)
		goto end;

	oauth2_debug(log, "restored session from cache: %s", value);

	rc = true;

end:

	if (key)
		oauth2_mem_free(key);
	if (value)
		oauth2_mem_free(value);

	return rc;
}

bool oauth2_session_save_cache(oauth2_log_t *log,
			       const oauth2_cfg_session_t *cfg,
			       const oauth2_http_request_t *request,
			       oauth2_http_response_t *response, json_t *json)
{
	bool rc = false;
	const char *name = NULL, *path = NULL;
	char *key = NULL, *value = NULL;

	value = oauth2_json_encode(log, json, 0);
	if (value == NULL)
		goto end;

	if (oauth2_json_string_get(log, json, OAUTH_SESSION_KEY_ID, &key,
				   NULL) == false) {
		oauth2_error(log, "no session identifier found in session");
		goto end;
	}

	if (oauth2_cache_set(log, cfg->cache, key, value,
			     oauth2_cfg_session_inactivity_timeout_s_get(
				 log, cfg)) == false) {
		oauth2_error(log, "could not store session in cache");
		goto end;
	}

	name = oauth2_cfg_session_cookie_name_get(log, cfg);
	path = oauth2_cfg_session_cookie_path_get(log, cfg);

	rc = oauth2_http_response_cookie_set(
	    log, response, name, key, path,
	    oauth2_http_request_is_secure(log, request), OAUTH2_CFG_TIME_UNSET);

end:

	if (key)
		oauth2_mem_free(key);
	if (value)
		oauth2_mem_free(value);

	return rc;
}

#define OAUTH2_SESSION_ID_LENGTH 16

static char *oauth2_session_id_generate(oauth2_log_t *log)
{
	return oauth2_rand_str(log, OAUTH2_SESSION_ID_LENGTH);
}

bool oauth2_session_load(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			 oauth2_http_request_t *request,
			 oauth2_session_rec_t **session)
{
	bool rc = false;
	json_t *json = NULL, *json_ptr = NULL;
	oauth2_session_load_callback_t *session_load_callback = NULL;
	json_int_t expiry = 0, start = 0;
	oauth2_time_t now = 0;

	oauth2_debug(log, "enter");

	if (session == NULL)
		goto end;

	*session = oauth2_session_rec_init(log);

	if (*session == NULL)
		goto end;

	session_load_callback = oauth2_cfg_session_load_callback_get(log, cfg);
	if (session_load_callback == NULL)
		goto end;

	rc = session_load_callback(log, cfg, request, &json);

	if ((rc == false) || (json == NULL)) {
		if ((rc) && ((*session)->id == NULL))
			(*session)->id = oauth2_session_id_generate(log);
		goto end;
	}

	now = oauth2_time_now_sec();

	if (oauth2_json_number_get(log, json, OAUTH_SESSION_KEY_START, &start,
				   0) == false)
		goto end;
	if (now >= start + oauth2_cfg_session_max_duration_s_get(log, cfg)) {
		oauth2_warn(log,
			    "session has exceeded maximum duration; "
			    "start=" OAUTH2_TIME_T_FORMAT
			    " expiry=" OAUTH2_TIME_T_FORMAT
			    " now=" OAUTH2_TIME_T_FORMAT "",
			    start,
			    oauth2_cfg_session_max_duration_s_get(log, cfg),
			    now);
		rc = false;
		goto end;
	}
	(*session)->start = start;

	if (oauth2_json_number_get(log, json, OAUTH_SESSION_KEY_EXPIRY, &expiry,
				   0) == false)
		goto end;
	if (now >= expiry) {
		oauth2_warn(log, "session has expired");
		// TODO: refactor and/or remove from cache?
		oauth2_session_rec_free(log, *session);
		*session = oauth2_session_rec_init(log);
		(*session)->id = oauth2_session_id_generate(log);
		rc = true;
		goto end;
	}
	(*session)->expiry = expiry;

	if (oauth2_json_string_get(log, json, OAUTH_SESSION_KEY_ID,
				   &(*session)->id, NULL) == false)
		goto end;

	if (oauth2_json_string_get(log, json, OAUTH_SESSION_KEY_USER,
				   &(*session)->user, NULL) == false)
		goto end;

	if (oauth2_json_string_get(log, json, OAUTH_SESSION_KEY_ID_TOKEN,
				   &(*session)->id_token, NULL) == false)
		goto end;

	if (oauth2_json_object_get(log, json, OAUTH_SESSION_KEY_ID_TOKEN_CLAIMS,
				   &json_ptr) == false)
		goto end;
	oauth2_session_rec_id_token_claims_set(log, *session, json_ptr);
	if (json_ptr)
		json_decref(json_ptr);

	if (oauth2_json_object_get(log, json, OAUTH_SESSION_KEY_USERINFO_CLAIMS,
				   &json_ptr) == false)
		goto end;
	oauth2_session_rec_userinfo_claims_set(log, *session, json_ptr);
	if (json_ptr)
		json_decref(json_ptr);

end:

	if (json)
		json_decref(json);

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

bool oauth2_session_handle(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			   const oauth2_http_request_t *request,
			   oauth2_http_response_t *response,
			   oauth2_session_rec_t *session)
{

	bool rc = false;
	bool needs_save = false;

	/*
	 * reset the session inactivity timer
	 * but only do this once per 10% of the inactivity timeout interval
	 * (with a max to 60 seconds) for performance reasons
	 *
	 * now there's a small chance that the session ends 10% (or a minute)
	 * earlier than configured/expected cq. when there's a request after a
	 * recent save (so no update) and then no activity happens until a
	 * request comes in just before the session should expire
	 * ("recent" and "just before" refer to 10%-with-a-max-of-60-seconds of
	 * the inactivity interval after the start/last-update and before the
	 * expiry of the session respectively)
	 *
	 * this is be deemed acceptable here because of performance gain
	 */
	oauth2_time_t interval =
	    oauth2_cfg_session_inactivity_timeout_s_get(log, cfg);
	oauth2_time_t now = oauth2_time_now_sec();
	oauth2_time_t slack = interval / 10;
	if (slack > 60)
		slack = 60;
	if (session->expiry - now < interval - slack) {
		// session->expiry = now + interval;
		needs_save = true;
	}

	oauth2_debug(log,
		     "session inactivity timeout: " OAUTH2_TIME_T_FORMAT
		     ", interval: " OAUTH2_TIME_T_FORMAT "",
		     session->expiry - now, interval);

	if (needs_save)
		rc = oauth2_session_save(log, cfg, request, response, session);
	else
		rc = true;

	return rc;
}

bool oauth2_session_save(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			 const oauth2_http_request_t *request,
			 oauth2_http_response_t *response,
			 oauth2_session_rec_t *session)
{
	bool rc = false;
	json_t *json = NULL;
	oauth2_session_save_callback_t *session_save_callback = NULL;

	if (session == NULL)
		goto end;

	json = json_object();
	if (json == NULL)
		goto end;

	if (session->start > 0)
		json_object_set_new(json, OAUTH_SESSION_KEY_START,
				    json_integer(session->start));

	if (session->expiry == 0) {
		oauth2_debug(
		    log,
		    "setting expiry according to "
		    "cfg->inactivity_timeout_s=" OAUTH2_TIME_T_FORMAT "",
		    oauth2_cfg_session_inactivity_timeout_s_get(log, cfg));
		session->expiry =
		    oauth2_time_now_sec() +
		    oauth2_cfg_session_inactivity_timeout_s_get(log, cfg);
	}

	if (session->expiry > 0)
		json_object_set_new(json, OAUTH_SESSION_KEY_EXPIRY,
				    json_integer(session->expiry));

	if (session->id)
		json_object_set_new(json, OAUTH_SESSION_KEY_ID,
				    json_string(session->id));

	if (session->user)
		json_object_set_new(json, OAUTH_SESSION_KEY_USER,
				    json_string(session->user));

	if (session->id_token)
		json_object_set_new(json, OAUTH_SESSION_KEY_ID_TOKEN,
				    json_string(session->id_token));

	if (session->id_token_claims)
		json_object_set(json, OAUTH_SESSION_KEY_ID_TOKEN_CLAIMS,
				session->id_token_claims);

	if (session->userinfo_claims)
		json_object_set(json, OAUTH_SESSION_KEY_USERINFO_CLAIMS,
				session->userinfo_claims);

	session_save_callback = oauth2_cfg_session_save_callback_get(log, cfg);
	if (session_save_callback == NULL)
		goto end;

	rc = session_save_callback(log, cfg, request, response, json);

end:

	if (json)
		json_decref(json);

	return rc;
}
