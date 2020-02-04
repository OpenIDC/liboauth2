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

#include "oauth2/session.h"
#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include "cfg_int.h"
#include "util_int.h"

typedef struct oauth2_session_rec_t {
	char *user;
	json_t *id_token_claims;
} oauth2_session_rec_t;

oauth2_session_rec_t *oauth2_session_rec_init(oauth2_log_t *log)
{
	oauth2_session_rec_t *s = (oauth2_session_rec_t *)oauth2_mem_alloc(
	    sizeof(oauth2_session_rec_t));
	s->user = NULL;
	s->id_token_claims = NULL;
	return s;
}

void oauth2_session_rec_free(oauth2_log_t *log, oauth2_session_rec_t *s)
{
	if (s->user)
		oauth2_mem_free(s->user);
	if (s->id_token_claims)
		json_decref(s->id_token_claims);
	if (s)
		oauth2_mem_free(s);
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(session, rec, user, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_GET(session, rec, id_token_claims, json_t *)

bool oauth2_session_rec_id_token_claims_set(oauth2_log_t *log,
					    oauth2_session_rec_t *session,
					    json_t *id_token)
{
	char *s_id_token = oauth2_json_encode(log, id_token, 0);
	oauth2_debug(log, "%s", s_id_token);
	session->id_token_claims = json_incref(id_token);
	oauth2_mem_free(s_id_token);
	return true;
}

#define OAUTH_SESSION_KEY_USER "u"
#define OAUTH_SESSION_ID_TOKEN_CLAIMS "i"

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

	rc = oauth2_jose_jwt_decrypt(
	    log, oauth2_cfg_session_passphrase_get(log, cfg), value, json);

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
	const char *name = NULL;
	char *value = NULL;

	if (oauth2_jose_jwt_encrypt(log,
				    oauth2_cfg_session_passphrase_get(log, cfg),
				    json, &value) == false)
		goto end;

	name = oauth2_cfg_session_cookie_name_get(log, cfg);

	// TODO: get cookie path from config
	rc = oauth2_http_response_cookie_set(log, response, name, value, "/");

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

	//	if (oauth2_cache_get(log, cfg->cache, key, &value) == false)
	//		goto end;

	if (value == NULL) {
		oauth2_debug(log, "no session found in cache");
		rc = true;
		goto end;
	}

	if (oauth2_json_decode_object(log, value, json) == false)
		goto end;

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
	const char *name = NULL;
	char *key = NULL, *value = NULL;

	value = oauth2_json_encode(log, json, 0);
	if (value == NULL)
		goto end;

	// TODO:
	key = "";

	// TODO: set to inactivity time out?
	//	if (oauth2_cache_set(log, cfg->cache, key, value, cfg->expiry_s)
	//== false) 		goto end;

	name = oauth2_cfg_session_cookie_name_get(log, cfg);

	// TODO: get cookie path from config
	rc = oauth2_http_response_cookie_set(log, response, name, key, "/");

end:

	if (key)
		oauth2_mem_free(key);
	if (value)
		oauth2_mem_free(value);

	return rc;
}

bool oauth2_session_load(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			 oauth2_http_request_t *request,
			 oauth2_session_rec_t **session)
{
	bool rc = false;
	json_t *json = NULL;
	oauth2_session_load_callback_t *session_load_callback = NULL;

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

	if ((rc == false) || (json == NULL))
		goto end;

	if (oauth2_json_string_get(log, json, OAUTH_SESSION_KEY_USER,
				   &(*session)->user, NULL) == false)
		goto end;

	if (oauth2_json_object_get(log, json, OAUTH_SESSION_ID_TOKEN_CLAIMS,
				   &(*session)->id_token_claims) == false)
		goto end;

end:

	if (json)
		json_decref(json);

	oauth2_debug(log, "return: %d", rc);

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

	if (session->user)
		json_object_set_new(json, OAUTH_SESSION_KEY_USER,
				    json_string(session->user));

	if (session->id_token_claims)
		json_object_set(json, OAUTH_SESSION_ID_TOKEN_CLAIMS,
				session->id_token_claims);

	session_save_callback = oauth2_cfg_session_save_callback_get(log, cfg);
	if (session_save_callback == NULL)
		goto end;

	rc = session_save_callback(log, cfg, request, response, json);

end:

	if (json)
		json_decref(json);

	return rc;
}
