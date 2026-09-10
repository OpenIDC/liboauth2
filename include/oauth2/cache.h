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

/**
 * @brief An opaque cache instance: a backend plus the per-instance
 *        key hashing and value encryption settings, created and
 *        registered by oauth2_cfg_set_cache() and retrieved with
 *        oauth2_cache_obtain().
 */
typedef struct oauth2_cache_t oauth2_cache_t;

/**
 * @name Cache backend interface
 * The function table a cache backend implements (see src/cache/). The
 * core calls a backend only through this table and does the generic
 * work around it: keys are hashed before the backend sees them (per
 * the instance's "key_hash_algo" option, SHA-256 hex by default,
 * "none" passes them through) and values are encrypted into a compact
 * JWE under a key derived from the crypto passphrase, and decrypted
 * again after a lookup, when the instance's "encrypt" option, or the
 * backend's default, says so. The built-in backends are registered on
 * first use; the table is public but there is no API to register
 * another one.
 * @{
 */

/**
 * @brief Backend init function: create the backend state of a new
 *        cache instance.
 *
 * Called with the new instance and the complete option list of the
 * cache directive from oauth2_cfg_set_cache() (cfg.h), or with an
 * empty list from oauth2_cache_obtain() for the default cache. The
 * backend reads its own options from the list and ignores the generic
 * "name", "encrypt", "key_hash_algo" and "passphrase_hash_algo" ones
 * that the core consumes afterwards; it must store its state in the
 * instance's impl member and point the instance's type member at its
 * own oauth2_cache_type_t, which the core relies on from then on.
 * Returns true on success, false on error.
 */
typedef bool (*oauth2_cache_init_function)(oauth2_log_t *log, oauth2_cache_t *,
					   const oauth2_nv_list_t *options);

/**
 * @brief Backend post-config function: complete the setup in the
 *        parent process.
 *
 * Called once, right after init and before the server forks its
 * workers, so this is where process-shared resources are created: the
 * "shm" backend creates its mutex and shared memory segment and clears
 * the slots, "file" creates its mutex, "memcache" and "redis" have
 * nothing to do. Returns true on success, false on error, which fails
 * the cache directive.
 */
typedef bool (*oauth2_cache_post_config_function)(oauth2_log_t *log,
						  oauth2_cache_t *);

/**
 * @brief Backend child-init function: attach a forked worker process.
 *
 * Meant to be called in each worker process after the fork; only the
 * "shm" backend uses it, to attach to its shared memory segment, the
 * others return true without doing anything. Returns true on success,
 * false on error.
 */
typedef bool (*oauth2_cache_child_init_function)(oauth2_log_t *log,
						 oauth2_cache_t *);

/**
 * @brief Backend get function: look up a hashed key.
 *
 * Called with the key already hashed by the core. The backend sets the
 * value pointer to the stored value as a newly allocated string, which
 * the core decrypts when the instance encrypts and releases with
 * oauth2_mem_free(), or to NULL on a miss, which includes an entry
 * that has expired. Returns true when the lookup was performed, hit or
 * miss, false on error.
 */
typedef bool (*oauth2_cache_get_function)(oauth2_log_t *log, oauth2_cache_t *,
					  const char *key, char **value);

/**
 * @brief Backend set function: store a value under a hashed key.
 *
 * Called with the key already hashed and the value already encrypted
 * by the core when the instance encrypts; the expiry is the
 * time-to-live in seconds. A NULL value removes the entry. Returns
 * true when stored or removed, false on error.
 */
typedef bool (*oauth2_cache_set_function)(oauth2_log_t *log, oauth2_cache_t *,
					  const char *key, const char *value,
					  oauth2_time_t expiry);

/**
 * @brief Backend free function: release the backend state.
 *
 * Called when the registered cache instances are released at
 * oauth2_shutdown() (util.h), after the core released its own
 * members; must free the impl member and whatever it holds. The
 * return value is ignored.
 */
typedef bool (*oauth2_cache_free_function)(oauth2_log_t *log, oauth2_cache_t *);

/**
 * @brief The descriptor of a cache backend: one static instance per
 *        backend (oauth2_cache_shm, oauth2_cache_file, ...), pointed
 *        at by every cache instance of that type.
 */
typedef struct oauth2_cache_type_t {
	/** the type name that the type argument of oauth2_cfg_set_cache()
	 *  selects: "shm", "file", "memcache" or "redis" */
	const char *name;
	/** whether values are encrypted unless the instance's "encrypt"
	 *  option says otherwise: false for "shm", whose memory does not
	 *  leave the process tree, true for the other backends */
	bool encrypt_by_default;
	/** see oauth2_cache_init_function */
	oauth2_cache_init_function init;
	/** see oauth2_cache_post_config_function */
	oauth2_cache_post_config_function post_config;
	/** see oauth2_cache_child_init_function */
	oauth2_cache_child_init_function child_init;
	/** see oauth2_cache_get_function */
	oauth2_cache_get_function get;
	/** see oauth2_cache_set_function */
	oauth2_cache_set_function set;
	/** see oauth2_cache_free_function */
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
 * @brief Attach a forked worker process to a cache.
 *
 * Calls the backend's child-init function (see
 * oauth2_cache_child_init_function); to be called in each worker
 * process after the fork for every cache obtained there.
 *
 * @param log   the log handle to use
 * @param cache the cache to attach to
 * @return true on success or when the backend has nothing to do, false
 *         on error or for a NULL cache
 */
bool oauth2_cache_child_init(oauth2_log_t *log, oauth2_cache_t *cache);

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
