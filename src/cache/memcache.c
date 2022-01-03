/***************************************************************************
 *
 * Copyright (C) 2018-2022 - ZmartZone Holding BV - www.zmartzone.eu
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

#include <string.h>

#include <oauth2/cache.h>
#include <oauth2/ipc.h>
#include <oauth2/mem.h>

#include "cache_int.h"
#include <libmemcached/memcached.h>

typedef struct oauth2_cache_impl_memcache_t {
	memcached_st *memc;
} oauth2_cache_impl_memcache_t;

oauth2_cache_type_t oauth2_cache_memcache;

static bool oauth2_cache_memcache_init(oauth2_log_t *log, oauth2_cache_t *cache,
				       const oauth2_nv_list_t *options)
{
	bool rc = false;
	oauth2_cache_impl_memcache_t *impl = NULL;
	const char *config_string = NULL;

	oauth2_debug(log, "enter");

	impl = oauth2_mem_alloc(sizeof(oauth2_cache_impl_memcache_t));
	if (impl == NULL)
		goto end;

	cache->impl = impl;
	cache->type = &oauth2_cache_memcache;

	config_string = oauth2_nv_list_get(log, options, "config_string");
	if (config_string == NULL)
		config_string = "--SERVER=localhost";

	impl->memc = memcached(config_string, strlen(config_string));
	if (impl->memc == NULL) {
		oauth2_error(log, "call to memcached() failed");
		goto end;
	}

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_memcache_free(oauth2_log_t *log, oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_memcache_t *impl =
	    (oauth2_cache_impl_memcache_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	if (impl->memc) {
		memcached_free(impl->memc);
		impl->memc = NULL;
	}

	oauth2_mem_free(impl);
	cache->impl = NULL;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_memcache_post_config(oauth2_log_t *log,
					      oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_memcache_t *impl =
	    (oauth2_cache_impl_memcache_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	//...

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_memcache_child_init(oauth2_log_t *log,
					     oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_memcache_t *impl =
	    (oauth2_cache_impl_memcache_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	//...

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_memcache_get(oauth2_log_t *log, oauth2_cache_t *cache,
				      const char *key, char **value)
{

	bool rc = false;
	memcached_return mrc;
	size_t len;
	uint32_t flags;
	oauth2_cache_impl_memcache_t *impl =
	    (oauth2_cache_impl_memcache_t *)cache->impl;

	oauth2_debug(log, "enter");

	if ((impl == NULL) || (impl->memc == NULL))
		goto end;

	*value = NULL;

	*value =
	    memcached_get(impl->memc, key, strlen(key), &len, &flags, &mrc);

	if ((mrc != MEMCACHED_SUCCESS) && (mrc != MEMCACHED_NOTFOUND)) {
		oauth2_error(log, "memcached_get failed: %s\n",
			     memcached_strerror(impl->memc, mrc));
		goto end;
	}

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_memcache_set(oauth2_log_t *log, oauth2_cache_t *cache,
				      const char *key, const char *value,
				      oauth2_time_t ttl_s)
{
	bool rc = false;
	memcached_return mrc;
	uint32_t flags = 0;
	oauth2_cache_impl_memcache_t *impl =
	    (oauth2_cache_impl_memcache_t *)cache->impl;

	oauth2_debug(log, "enter");

	if ((impl == NULL) || (impl->memc == NULL))
		goto end;

	mrc = memcached_set(impl->memc, key, strlen(key), value,
			    value ? strlen(value) : 0, (time_t)ttl_s, flags);

	if (mrc != MEMCACHED_SUCCESS) {
		oauth2_error(log, "memcached_set failed: %s\n",
			     memcached_strerror(impl->memc, mrc));
		goto end;
	}

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

OAUTH2_CACHE_TYPE_DECLARE(memcache, true)
