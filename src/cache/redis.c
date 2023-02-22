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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/
#ifdef LIBAUTH2_CACHE_REDIS_ENABLED

#include <string.h>

#include <oauth2/cache.h>
#include <oauth2/ipc.h>
#include <oauth2/mem.h>
#include <oauth2/util.h>

#include "cache_int.h"
#include "hiredis/hiredis.h"

typedef struct oauth2_cache_impl_redis_t {
	oauth2_ipc_mutex_t *mutex;
	char *host_str;
	oauth2_uint_t port;
	char *passwd;
	redisContext *ctx;
} oauth2_cache_impl_redis_t;

oauth2_cache_type_t oauth2_cache_redis;

static bool oauth2_cache_redis_init(oauth2_log_t *log, oauth2_cache_t *cache,
				    const oauth2_nv_list_t *options)
{
	bool rc = false;
	oauth2_cache_impl_redis_t *impl = NULL;
	const char *v = NULL;

	oauth2_debug(log, "enter");

	impl = oauth2_mem_alloc(sizeof(oauth2_cache_impl_redis_t));
	if (impl == NULL)
		goto end;

	cache->impl = impl;
	cache->type = &oauth2_cache_redis;

	impl->mutex = oauth2_ipc_mutex_init(log);
	if (impl->mutex == NULL)
		goto end;

	// TODO: #define and/or parse host:port tuple in one step
	v = oauth2_nv_list_get(log, options, "host");
	if (v == NULL)
		v = "localhost";
	impl->host_str = oauth2_strdup(v);

	v = oauth2_nv_list_get(log, options, "port");
	impl->port = oauth2_parse_uint(log, v, 6379);

	v = oauth2_nv_list_get(log, options, "password");
	impl->passwd = v ? oauth2_strdup(v) : NULL;

	impl->ctx = NULL;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_redis_free(oauth2_log_t *log, oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_redis_t *impl =
	    (oauth2_cache_impl_redis_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	if (impl->mutex) {
		oauth2_ipc_mutex_lock(log, impl->mutex);

		if (impl->ctx) {
			redisFree(impl->ctx);
			impl->ctx = NULL;
		}

		oauth2_ipc_mutex_unlock(log, impl->mutex);
		oauth2_ipc_mutex_free(log, impl->mutex);

		impl->mutex = NULL;
	}

	if (impl->host_str)
		oauth2_mem_free(impl->host_str);
	if (impl->passwd)
		oauth2_mem_free(impl->passwd);

	oauth2_mem_free(impl);
	cache->impl = NULL;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_redis_post_config(oauth2_log_t *log,
					   oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_redis_t *impl =
	    (oauth2_cache_impl_redis_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	rc = oauth2_ipc_mutex_post_config(log, impl->mutex);
	if (rc == false)
		goto end;

	// TODO: connect to the server here?

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_redis_child_init(oauth2_log_t *log,
					  oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_redis_t *impl =
	    (oauth2_cache_impl_redis_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	// TODO: nothing?

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _oauth2_cache_redis_connect(oauth2_log_t *log,
					oauth2_cache_impl_redis_t *impl)
{
	bool rc = false;

	if (impl->ctx) {
		rc = true;
		goto end;
	}

	impl->ctx = redisConnect(impl->host_str, impl->port);

	if ((impl->ctx == NULL) || (impl->ctx->err != 0)) {
		oauth2_error(log,
			     "failed to connect to Redis server (%s:%d): '%s'",
			     impl->host_str, impl->port,
			     impl->ctx != NULL ? impl->ctx->errstr : "");
		redisFree(impl->ctx);
		impl->ctx = NULL;
		goto end;
	}

	oauth2_debug(
	    log,
	    "successfully connected to Redis server (%s:" OAUTH2_UINT_FORMAT
	    ")",
	    impl->host_str, impl->port);

	rc = true;

end:

	return rc;
}

#define OIDC_REDIS_MAX_TRIES 2

static redisReply *_oauth2_cache_redis_command(oauth2_log_t *log,
					       oauth2_cache_impl_redis_t *impl,
					       const char *command)
{

	redisReply *reply = NULL;
	int i = 0;

	oauth2_debug(log, "enter: %s", command);

	for (i = 0; i < OIDC_REDIS_MAX_TRIES; i++) {

		if (_oauth2_cache_redis_connect(log, impl) == false)
			break;

		if (impl->passwd != NULL) {
			reply =
			    redisCommand(impl->ctx, "AUTH %s", impl->passwd);
			if ((reply == NULL) ||
			    (reply->type == REDIS_REPLY_ERROR))
				oauth2_error(
				    log,
				    "Redis AUTH command (attempt=%d to "
				    "%s:" OAUTH2_UINT_FORMAT
				    ") failed: '%s' [%s]",
				    i, impl->host_str, impl->port,
				    impl->ctx->errstr,
				    reply ? reply->str : "<n/a>");

			if (reply) {
				freeReplyObject(reply);
				reply = NULL;
			}
		}

		reply = redisCommand(impl->ctx, command);

		if ((reply != NULL) && (reply->type != REDIS_REPLY_ERROR))
			break;

		oauth2_error(
		    log,
		    "Redis command (attempt=%d to %s:" OAUTH2_UINT_FORMAT
		    ") failed, disconnecting: '%s' [%s]",
		    i, impl->host_str, impl->port, impl->ctx->errstr,
		    reply ? reply->str : "<n/a>");

		if (reply) {
			freeReplyObject(reply);
			reply = NULL;
		}

		redisFree(impl->ctx);
		impl->ctx = NULL;
	}

	oauth2_debug(log, "leave: %p", reply);

	return reply;
}

static bool oauth2_cache_redis_get(oauth2_log_t *log, oauth2_cache_t *cache,
				   const char *key, char **value)
{

	bool rc = false;
	redisReply *reply = NULL;
	char *cmd = NULL;
	oauth2_cache_impl_redis_t *impl =
	    (oauth2_cache_impl_redis_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	*value = NULL;

	if (oauth2_ipc_mutex_lock(log, impl->mutex) == false)
		goto end;

	cmd = oauth2_stradd(NULL, "GET", " ", key);
	reply = _oauth2_cache_redis_command(log, impl, cmd);
	if (reply == NULL)
		goto unlock;

	if (reply->type == REDIS_REPLY_NIL) {
		rc = true;
		goto unlock;
	}

	// TODO: should we not store the \0 and/or allow binary data?
	if (reply->len != strlen(reply->str)) {
		oauth2_error(
		    log, "redisCommand reply->len != strlen(reply->str): '%s'",
		    reply->str);
		goto unlock;
	}

	*value = oauth2_strndup(reply->str, reply->len);

	rc = true;

unlock:

	oauth2_ipc_mutex_unlock(log, impl->mutex);

end:

	if (cmd)
		oauth2_mem_free(cmd);
	if (reply)
		freeReplyObject(reply);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

#define OAUTH2_UINT_MAX_STR 64

static bool oauth2_cache_redis_set(oauth2_log_t *log, oauth2_cache_t *cache,
				   const char *key, const char *value,
				   oauth2_time_t ttl_s)
{
	bool rc = false;
	redisReply *reply = NULL;
	char *cmd = NULL;
	char s_timeout[OAUTH2_UINT_MAX_STR];
	oauth2_cache_impl_redis_t *impl =
	    (oauth2_cache_impl_redis_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	if (oauth2_ipc_mutex_lock(log, impl->mutex) == false)
		goto end;

	if (value) {

		oauth2_snprintf(s_timeout, OAUTH2_UINT_MAX_STR,
				"" OAUTH2_TIME_T_FORMAT "", ttl_s);
		cmd = oauth2_strdup("SETEX ");
		cmd = oauth2_stradd(cmd, key, " ", s_timeout);
		cmd = oauth2_stradd(cmd, " ", value, NULL);

	} else {

		cmd = oauth2_stradd(NULL, "DEL", " ", key);
	}

	reply = _oauth2_cache_redis_command(log, impl, cmd);
	if (reply == NULL)
		goto unlock;

	rc = (reply->type != REDIS_REPLY_ERROR);

unlock:

	oauth2_ipc_mutex_unlock(log, impl->mutex);

end:

	if (cmd)
		oauth2_mem_free(cmd);
	if (reply)
		freeReplyObject(reply);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

OAUTH2_CACHE_TYPE_DECLARE(redis, true)
#endif