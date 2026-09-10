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
 * `oauth2_cfg_session_t` holds the session settings: storage type,
 * cookie name and path, inactivity timeout, maximum duration, the
 * backing cache (for the "cache" type) and the load/save callbacks
 * implementing the storage type. Configurations are registered under
 * a name by oauth2_cfg_session_set_options() and selected through the
 * "session" option of oauth2_cfg_openidc_set_options() (openidc.h);
 * when none was configured, a default one of the "cache" type is
 * created on first use.
 * @{
 */

/**
 * @brief Opaque session configuration.
 *
 * A new object has its storage type, cookie name and path, timeouts,
 * cache and callbacks unset, in which case the getters below return
 * their defaults. Only the `_init` and `_free` functions of the
 * declaration are implemented; `_clone` and `_merge` are not. Freeing
 * the object does not free the cache it refers to, which is owned by
 * the cache registry (cache.h).
 */
OAUTH2_CFG_TYPE_DECLARE(cfg, session)

/**
 * @brief The name of the session cookie, default "openidc_session";
 *        set by the "cookie.name" option. The getter returns a
 *        borrowed pointer, also for a NULL configuration.
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, cookie_name, char *)
/**
 * @brief The path attribute of the session cookie, default "/"; set
 *        by the "cookie.path" option. The getter returns a borrowed
 *        pointer, also for a NULL configuration.
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, cookie_path, char *)
/**
 * @brief The inactivity timeout in seconds, default 300; set by the
 *        "inactivity_timeout" option. A session expires when no
 *        request refreshed it for that long: oauth2_session_save()
 *        sets the expiry that far ahead and oauth2_session_handle()
 *        moves it forward on activity; for the "cache" type it is also
 *        the time-to-live of the cache entry.
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, inactivity_timeout_s,
			       oauth2_time_t)
/**
 * @brief The maximum session duration in seconds, counted from the
 *        session start, default 28800 (8 hours); set by the
 *        "max_duration" option. A stored session that started longer
 *        ago fails to load.
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, max_duration_s, oauth2_time_t)
/**
 * @brief The cache holding the session records of the "cache" storage
 *        type, obtained by name through the "cache" option (the
 *        default cache when absent); NULL for the "cookie" type. The
 *        getter returns a borrowed pointer and requires a non-NULL
 *        configuration.
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, cache, oauth2_cache_t *)

/**
 * @brief Callback loading the stored session record for a request.
 *
 * Implements the load half of a storage type: the built-in "cookie"
 * callback takes the encrypted record from the session cookie, the
 * "cache" callback looks the cookie value up as the session identifier
 * in the configured cache. Both remove the session cookie from the
 * request while reading it.
 *
 * @param log     the log handle to use
 * @param cfg     the session configuration
 * @param request the incoming request carrying the session cookie
 * @param json    set to the stored record as a new JSON object, to be
 *                released by the caller with json_decref(), or left
 *                NULL when the request carries no session cookie or
 *                no record is stored for it
 * @return true when the lookup was performed, also without a result,
 *         false when the stored record could not be decrypted, read
 *         or parsed
 */
typedef bool(oauth2_session_load_callback_t)(oauth2_log_t *log,
					     const oauth2_cfg_session_t *cfg,
					     oauth2_http_request_t *request,
					     json_t **json);
/**
 * @brief Callback persisting a session record and setting the cookie.
 *
 * Implements the save half of a storage type: the built-in "cookie"
 * callback encrypts the record into the session cookie, the "cache"
 * callback stores it in the configured cache under the record's
 * session identifier, with the inactivity timeout as time-to-live, and
 * sets the cookie to that identifier. Both set the cookie with the
 * configured name and path, with the Secure attribute when the request
 * came in over https and without Max-Age, so that it lasts for the
 * browser session.
 *
 * @param log      the log handle to use
 * @param cfg      the session configuration
 * @param request  the incoming request, consulted for its scheme
 * @param response the response to set the session cookie on
 * @param json     the record to store, borrowed
 * @return true when the record was stored and the cookie set, false on
 *         error
 */
typedef bool(oauth2_session_save_callback_t)(
    oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
    const oauth2_http_request_t *request, oauth2_http_response_t *response,
    json_t *json);

/**
 * @brief The load callback of the configured storage type; the getter
 *        returns the "cookie" one when unset.
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, load_callback,
			       oauth2_session_load_callback_t *)
/**
 * @brief The save callback of the configured storage type; the getter
 *        returns the "cookie" one when unset.
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(cfg, session, save_callback,
			       oauth2_session_save_callback_t *)

/**
 * @brief Configure the session settings from an option string.
 *
 * @param log     the log handle to use
 * @param cfg     the session configuration to populate, or NULL to
 *                create a new one
 * @param type    "cookie" (keep the session record in an encrypted
 *                cookie) or "cache" (keep it in a cache, referenced
 *                from the cookie)
 * @param options form-encoded parameters: "cookie.name",
 *                "cookie.path", "inactivity_timeout" and
 *                "max_duration" (both in seconds; a value that does
 *                not parse leaves the setting unset), for the "cache"
 *                type the "cache" name to use (the default cache when
 *                absent), and "name", the name the configuration is
 *                registered under for the "session" option of
 *                oauth2_cfg_openidc_set_options() (the default
 *                configuration when absent)
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

/**
 * @brief Opaque per-user session record.
 *
 * A new record has its start set to the current time, no expiry (0)
 * and no user, id_token or claims; `_clone` is not implemented. The
 * session identifier the "cache" storage type keys on is generated by
 * oauth2_session_load() and not exposed.
 */
OAUTH2_TYPE_DECLARE(session, rec);

/**
 * @brief The authenticated user; the OpenID Connect RP flow stores
 *        the "sub" claim of the id_token here. The setter copies the
 *        string and rejects NULL, the getter returns a borrowed
 *        pointer.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, user, char *)
/**
 * @brief The serialized id_token, for a binding that wants to keep it;
 *        the RP flow itself stores only its claims. The setter copies
 *        the string and rejects NULL, the getter returns a borrowed
 *        pointer.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, id_token, char *)
/**
 * @brief The claims of the verified id_token, a borrowed JSON object
 *        or NULL; set with oauth2_session_rec_id_token_claims_set().
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(session, rec, id_token_claims, json_t *)
/**
 * @brief The claims obtained from the userinfo endpoint, a borrowed
 *        JSON object or NULL; set with
 *        oauth2_session_rec_userinfo_claims_set().
 */
OAUTH2_TYPE_DECLARE_MEMBER_GET(session, rec, userinfo_claims, json_t *)
/**
 * @brief The time the session started, in seconds since the epoch:
 *        the creation time of a new record, restored from storage on
 *        load and checked against the maximum duration there.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, start, oauth2_time_t)
/**
 * @brief The time the session expires, in seconds since the epoch: 0
 *        in a new record, set to the current time plus the inactivity
 *        timeout by the first oauth2_session_save(), moved forward by
 *        oauth2_session_handle() on activity and restored from storage
 *        on load, where a passed expiry discards the session.
 */
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, expiry, oauth2_time_t)

/**
 * @brief Store the claims of the id_token in the session record.
 *
 * The record takes a reference of its own to the object, so the caller
 * keeps, and eventually releases, its own; a NULL object leaves the
 * record unchanged.
 *
 * @param log      the log handle to use
 * @param session  the session record
 * @param id_token the id_token claims as a JSON object
 * @return true
 */
bool oauth2_session_rec_id_token_claims_set(oauth2_log_t *log,
					    oauth2_session_rec_t *session,
					    json_t *id_token);
/**
 * @brief Store the userinfo claims in the session record.
 *
 * As oauth2_session_rec_id_token_claims_set(), for the claims obtained
 * from the userinfo endpoint.
 *
 * @param log             the log handle to use
 * @param session         the session record
 * @param userinfo_claims the userinfo claims as a JSON object
 * @return true
 */
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
 * Retrieves the stored record through the configuration's load
 * callback and validates it: a session that started longer ago than
 * the maximum duration or whose expiry has passed is dropped and
 * replaced by a new empty record, as is returned when the request
 * carries no session at all. A new record gets a fresh session
 * identifier.
 *
 * @param log     the log handle to use
 * @param c       the session configuration
 * @param r       the incoming HTTP request
 * @param session set to the newly allocated session record, to be
 *                released by the caller with oauth2_session_rec_free()
 * @return true when a session was loaded or a new one created, false
 *         on error
 */
bool oauth2_session_load(oauth2_log_t *log, const oauth2_cfg_session_t *c,
			 oauth2_http_request_t *r,
			 oauth2_session_rec_t **session);

/**
 * @brief Persist a session and set the session cookie on the response.
 *
 * Serializes the record - start, expiry, identifier, user, id_token
 * and claims - to JSON and hands it to the configuration's save
 * callback; a record without an expiry gets one set to the current
 * time plus the inactivity timeout first.
 *
 * @param log      the log handle to use
 * @param cfg      the session configuration
 * @param request  the incoming HTTP request
 * @param response the response to set the session cookie on
 * @param session  the session record to store
 * @return true when stored, false on error
 */
bool oauth2_session_save(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			 const oauth2_http_request_t *request,
			 oauth2_http_response_t *response,
			 oauth2_session_rec_t *session);

/**
 * @brief Refresh the stored session on an authenticated request.
 *
 * Moves the expiry forward to the current time plus the inactivity
 * timeout and saves the session again, but only when less than the
 * inactivity timeout minus a slack of 10% of it (at most 60 seconds)
 * remains until the expiry, so that a freshly saved session is not
 * written back on every request.
 *
 * @param log      the log handle to use
 * @param cfg      the session configuration
 * @param request  the incoming HTTP request
 * @param response the response to set the session cookie on
 * @param session  the session record loaded for the request
 * @return true when nothing needed saving or the save succeeded, false
 *         when it failed
 */
bool oauth2_session_handle(oauth2_log_t *log, const oauth2_cfg_session_t *cfg,
			   const oauth2_http_request_t *request,
			   oauth2_http_response_t *response,
			   oauth2_session_rec_t *session);
/** @} */

#endif /* _OAUTH2_SESSION_H_ */
