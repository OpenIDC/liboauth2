#ifndef _OAUTH2_SESSION_H_
#define _OAUTH2_SESSION_H_

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
 * @file session.h
 * @brief Cookie-based session management.
 *
 * Sessions carry the authenticated state of the OpenID Connect RP flow
 * (see openidc.h) across requests: a session record holds the user,
 * the id_token and its claims, the userinfo claims and the session
 * timestamps. Per the session configuration the record is stored
 * either in the session cookie itself ("cookie" type, encrypted) or in
 * a cache referenced from the cookie ("cache" type), and both an
 * inactivity timeout and a maximum session duration are enforced.
 */

#include "oauth2/cache.h"
#include "oauth2/openidc.h"
#include "oauth2/util.h"

/**
 * @name Session configuration
 * oauth2_cfg_session_t holds the session settings: storage type,
 * cookie name and path, inactivity timeout, maximum duration, the
 * backing cache (for the "cache" type) and the load/save callbacks
 * implementing the storage type.
 * @{
 */

OAUTH2_CFG_TYPE_DECLARE(cfg, session)
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, cookie_name, char *)
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, cookie_path, char *)
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, inactivity_timeout_s,
			       oauth2_time_t)
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, max_duration_s, oauth2_time_t)
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, cache, oauth2_cache_t *)

typedef bool(oauth2_session_load_callback_t)(oauth2_log_t *log,
					     const oauth2_cfg_session_t *cfg,
					     oauth2_http_request_t *request,
					     json_t **json);
typedef bool(oauth2_session_save_callback_t)(
    oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
    const oauth2_http_request_t *request, oauth2_http_response_t *response,
    json_t *json);

OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, load_callback,
			       oauth2_session_load_callback_t *)
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, save_callback,
			       oauth2_session_save_callback_t *)

/**
 * @brief Configure the session settings from an option string.
 *
 * @param log     the log handle to use
 * @param cfg     the session configuration to populate
 * @param type    "cookie" (keep the session record in an encrypted
 *                cookie) or "cache" (keep it in a cache, referenced
 *                from the cookie)
 * @param options form-encoded parameters: "cookie.name",
 *                "cookie.path", "inactivity_timeout" and
 *                "max_duration" (both in seconds), and for the
 *                "cache" type the "cache" name to use
 * @return NULL on success, an error string on failure
 */
char *oauth2_cfg_session_set_options(oauth2_log_t *log,
				     oauth2_cfg_session_t *cfg,
				     const char *type, const char *options);
/** @} */

/**
 * @name Session record
 * The per-user session state as loaded from and saved to the
 * configured storage.
 * @{
 */

OAUTH2_TYPE_DECLARE(session, rec);

OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, user, char *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, id_token, char *)
OAUTH2_TYPE_DECLARE_MEMBER_GET(session, rec, id_token_claims, json_t *)
OAUTH2_TYPE_DECLARE_MEMBER_GET(session, rec, userinfo_claims, json_t *)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, start, oauth2_time_t)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, expiry, oauth2_time_t)

bool oauth2_session_rec_id_token_claims_set(oauth2_log_t *log,
					    oauth2_session_rec_t *session,
					    json_t *id_token);
bool oauth2_session_rec_userinfo_claims_set(oauth2_log_t *log,
					    oauth2_session_rec_t *session,
					    json_t *userinfo_claims);
/** @} */

/**
 * @name Session lifecycle
 * @{
 */

/**
 * @brief Load the session associated with an incoming request.
 *
 * Loads and validates the session referenced by the request's session
 * cookie - dropping it when the inactivity timeout or maximum duration
 * has passed - and returns a new empty session record when there is
 * none.
 *
 * @param log     the log handle to use
 * @param c       the session configuration
 * @param r       the incoming HTTP request
 * @param session set to the newly allocated session record, to be
 *                released by the caller with oauth2_session_rec_free()
 * @return true on success, false on error
 */
bool oauth2_session_load(oauth2_log_t *log, const oauth2_cfg_session_t *c,
			 oauth2_http_request_t *r,
			 oauth2_session_rec_t **session);

/**
 * @brief Persist a session and set the session cookie on the response.
 */
bool oauth2_session_save(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			 const oauth2_http_request_t *request,
			 oauth2_http_response_t *response,
			 oauth2_session_rec_t *session);

/**
 * @brief Handle an existing session on an authenticated request.
 *
 * Resets the session inactivity timer and saves the session when
 * needed; the reset is rate-limited to once per 10% of the inactivity
 * timeout interval (max 60 seconds) for performance reasons.
 */
bool oauth2_session_handle(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			   const oauth2_http_request_t *request,
			   oauth2_http_response_t *response,
			   oauth2_session_rec_t *session);
/** @} */

#endif /* _OAUTH2_SESSION_H_ */
