#ifndef _OAUTH2_CACHE_H_
#define _OAUTH2_CACHE_H_

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
 * @file cache.h
 * @brief Pluggable named caches.
 *
 * Cache instances live behind a backend vtable - "shm" (shared
 * memory) and "file" are always built, "memcache" and "redis" when
 * their client libraries are found - and are created and registered
 * under a name with oauth2_cfg_set_cache() (cfg.h), then retrieved
 * with oauth2_cache_obtain(). Keys are hashed and values are
 * transparently encrypted, depending on per-instance settings and the
 * backend's default. Caches back token verification results, session
 * data, provider documents, DPoP replay detection, etc.
 */

#include "oauth2/log.h"
#include "oauth2/util.h"

typedef struct oauth2_cache_t oauth2_cache_t;

/**
 * @name Cache backend interface
 * The function table a cache backend implements (see src/cache/);
 * encrypt_by_default determines whether values in this backend are
 * encrypted unless overridden by the instance's "encrypt" option.
 * @{
 */

typedef bool (*oauth2_cache_init_function)(oauth2_log_t *log, oauth2_cache_t *,
					   const oauth2_nv_list_t *options);
typedef bool (*oauth2_cache_post_config_function)(oauth2_log_t *log,
						  oauth2_cache_t *);
typedef bool (*oauth2_cache_child_init_function)(oauth2_log_t *log,
						 oauth2_cache_t *);
typedef bool (*oauth2_cache_get_function)(oauth2_log_t *log, oauth2_cache_t *,
					  const char *key, char **value);
typedef bool (*oauth2_cache_set_function)(oauth2_log_t *log, oauth2_cache_t *,
					  const char *key, const char *value,
					  oauth2_time_t expiry);
typedef bool (*oauth2_cache_free_function)(oauth2_log_t *log, oauth2_cache_t *);

typedef struct oauth2_cache_type_t {
	const char *name;
	bool encrypt_by_default;
	oauth2_cache_init_function init;
	oauth2_cache_post_config_function post_config;
	oauth2_cache_child_init_function child_init;
	oauth2_cache_get_function get;
	oauth2_cache_set_function set;
	oauth2_cache_free_function free;
} oauth2_cache_type_t;
/** @} */

/**
 * @brief Retrieve a registered cache instance.
 *
 * When no cache has been configured at all, a default shared-memory
 * cache is created and registered first.
 *
 * @param log  the log handle to use
 * @param name the name the cache was registered under (the "name"
 *             option to oauth2_cfg_set_cache()), or NULL for the
 *             default cache
 * @return a borrowed pointer to the cache, or NULL on error
 */
oauth2_cache_t *oauth2_cache_obtain(oauth2_log_t *log, const char *name);

/**
 * @brief Look up a key in a cache.
 *
 * @param log   the log handle to use
 * @param ctx   the cache to look up in
 * @param key   the key to look up
 * @param value on a hit, set to the (decrypted) value as a newly
 *              allocated string, to be released with
 *              oauth2_mem_free(); set to NULL on a miss
 * @return true when the lookup was performed successfully (hit or
 *         miss), false on error
 */
bool oauth2_cache_get(oauth2_log_t *log, oauth2_cache_t *ctx, const char *key,
		      char **value);

/**
 * @brief Store a key/value pair in a cache.
 *
 * @param log   the log handle to use
 * @param ctx   the cache to store in
 * @param key   the key to store the value under
 * @param value the value to store
 * @param ttl_s the time-to-live of the entry in seconds
 * @return true when stored successfully, false on error
 */
bool oauth2_cache_set(oauth2_log_t *log, oauth2_cache_t *ctx, const char *key,
		      const char *value, oauth2_time_t ttl_s);

#endif /* _OAUTH2_CACHE_H_ */
