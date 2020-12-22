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

#include <oauth2/cache.h>
#include <oauth2/ipc.h>
#include <oauth2/mem.h>
#include <oauth2/util.h>

#include <string.h>

#include "cache_int.h"

typedef struct oauth2_cache_impl_shm_t {
	oauth2_ipc_shm_t *shm;
	oauth2_ipc_mutex_t *mutex;
	oauth2_uint_t max_key_size;
	oauth2_uint_t max_val_size;
	oauth2_uint_t max_entries;
} oauth2_cache_impl_shm_t;

typedef struct oauth2_cache_shm_entry_t {
	oauth2_time_t access_s;
	oauth2_time_t expires_s;
	uint8_t key_and_value[];
} oauth2_cache_shm_entry_t;

#define OAUTH2_CACHE_SHM_KEY_OFFSET(ptr) (uint8_t *)&ptr->key_and_value[0]

#define OAUTH2_CACHE_SHM_VALUE_OFFSET(ptr, impl)                               \
	(uint8_t *)&ptr->key_and_value[impl->max_key_size]

#define OAUTH2_CACHE_SHM_SLOT_SIZE(impl)                                       \
	(sizeof(oauth2_cache_shm_entry_t) + impl->max_key_size +               \
	 impl->max_val_size)

#define OAUTH2_CACHE_SHM_ADD_OFFSET(ptr, implv)                                \
	ptr = (oauth2_cache_shm_entry_t *)((uint8_t *)ptr +                    \
					   OAUTH2_CACHE_SHM_SLOT_SIZE(impl))

#define OAUTH2_CACHE_SHM_MAX_KEY_SIZE "max_key_size"
#define OAUTH2_CACHE_SHM_MAX_VALUE_SIZE "max_val_size"
#define OAUTH2_CACHE_SHM_MAX_ENTRIES "max_entries"

#define OAUTH2_CACHE_SHM_MAX_KEY_SIZE_DEFAULT 65
#define OAUTH2_CACHE_SHM_MAX_VALUE_SIZE_DEFAULT 8193
#define OAUTH2_CACHE_SHM_MAX_ENTRIES_DEFAULT 1000

oauth2_cache_type_t oauth2_cache_shm;

static bool oauth2_cache_shm_init(oauth2_log_t *log, oauth2_cache_t *cache,
				  const oauth2_nv_list_t *options)
{
	bool rc = false;
	oauth2_cache_impl_shm_t *impl = NULL;

	oauth2_debug(log, "enter");

	impl = oauth2_mem_alloc(sizeof(oauth2_cache_impl_shm_t));
	if (impl == NULL)
		goto end;

	cache->impl = impl;
	cache->type = &oauth2_cache_shm;

	impl->mutex = oauth2_ipc_mutex_init(log);
	if (impl->mutex == NULL)
		goto end;

	impl->max_key_size = oauth2_parse_uint(
	    log,
	    oauth2_nv_list_get(log, options, OAUTH2_CACHE_SHM_MAX_KEY_SIZE),
	    OAUTH2_CACHE_SHM_MAX_KEY_SIZE_DEFAULT);
	impl->max_val_size = oauth2_parse_uint(
	    log,
	    oauth2_nv_list_get(log, options, OAUTH2_CACHE_SHM_MAX_VALUE_SIZE),
	    OAUTH2_CACHE_SHM_MAX_VALUE_SIZE_DEFAULT);
	impl->max_entries = oauth2_parse_uint(
	    log, oauth2_nv_list_get(log, options, OAUTH2_CACHE_SHM_MAX_ENTRIES),
	    OAUTH2_CACHE_SHM_MAX_ENTRIES_DEFAULT);

	oauth2_debug(log,
		     "creating shm cache: %s=" OAUTH2_UINT_FORMAT
		     " %s=" OAUTH2_UINT_FORMAT " %s=" OAUTH2_UINT_FORMAT "",
		     OAUTH2_CACHE_SHM_MAX_KEY_SIZE, impl->max_key_size,
		     OAUTH2_CACHE_SHM_MAX_VALUE_SIZE, impl->max_val_size,
		     OAUTH2_CACHE_SHM_MAX_ENTRIES, impl->max_entries);

	impl->shm = oauth2_ipc_shm_init(log, OAUTH2_CACHE_SHM_SLOT_SIZE(impl) *
						 impl->max_entries);
	if (impl->shm == NULL)
		goto end;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_shm_free(oauth2_log_t *log, oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_shm_t *impl = (oauth2_cache_impl_shm_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	if (impl->mutex != NULL) {
		oauth2_ipc_mutex_lock(log, impl->mutex);
		oauth2_ipc_shm_free(log, impl->shm);
		oauth2_ipc_mutex_unlock(log, impl->mutex);
		oauth2_ipc_mutex_free(log, impl->mutex);
		impl->mutex = NULL;
	}

	oauth2_mem_free(impl);
	cache->impl = NULL;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_shm_post_config(oauth2_log_t *log,
					 oauth2_cache_t *cache)
{
	bool rc = false;
	int i = 0;
	oauth2_cache_shm_entry_t *ptr = NULL;
	oauth2_cache_impl_shm_t *impl = (oauth2_cache_impl_shm_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	rc = oauth2_ipc_mutex_post_config(log, impl->mutex);
	if (rc == false)
		goto end;

	rc = oauth2_ipc_shm_post_config(log, impl->shm);
	if (rc == false)
		goto end;

	ptr = oauth2_ipc_shm_get(log, impl->shm);
	if (ptr == NULL) {
		oauth2_error(log, "oauth2_ipc_shm_get failed");
		goto end;
	}

	for (i = 0; i < impl->max_entries;
	     i++, OAUTH2_CACHE_SHM_ADD_OFFSET(ptr, impl)) {
		ptr->access_s = 0;
		ptr->expires_s = 0;
		*OAUTH2_CACHE_SHM_KEY_OFFSET(ptr) = '\0';
		*OAUTH2_CACHE_SHM_VALUE_OFFSET(ptr, impl) = '\0';
	}

	oauth2_debug(log,
		     "initialized shared memory with a cache size (# "
		     "entries) of: " OAUTH2_UINT_FORMAT
		     ", and a max (single) slot size of: " OAUTH2_UINT_FORMAT,
		     impl->max_entries, OAUTH2_CACHE_SHM_SLOT_SIZE(impl));

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_shm_child_init(oauth2_log_t *log,
					oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_shm_t *impl = (oauth2_cache_impl_shm_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	rc = oauth2_ipc_shm_child_init(log, impl->shm);
	if (rc == false)
		goto end;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_shm_check_key(oauth2_log_t *log,
				       oauth2_cache_impl_shm_t *impl,
				       const char *key)
{
	bool rc = true;
	if (strlen(key) >= impl->max_key_size) {
		oauth2_error(log,
			     "could not construct cache key since key size is "
			     "too large (%lu >= " OAUTH2_UINT_FORMAT ") : %s",
			     (unsigned long)strlen(key), impl->max_key_size,
			     key);
		rc = false;
	}
	return rc;
}

static bool oauth2_cache_shm_get(oauth2_log_t *log, oauth2_cache_t *cache,
				 const char *key, char **value)
{

	bool rc = false;
	int i = 0;
	oauth2_cache_shm_entry_t *ptr = NULL;
	const char *entry_key = NULL;
	oauth2_time_t now_s = 0;
	oauth2_cache_impl_shm_t *impl = (oauth2_cache_impl_shm_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	if (oauth2_cache_shm_check_key(log, impl, key) == false)
		goto end;

	*value = NULL;

	if (oauth2_ipc_mutex_lock(log, impl->mutex) == false)
		goto end;

	ptr = oauth2_ipc_shm_get(log, impl->shm);
	if (ptr == NULL)
		goto unlock;

	now_s = oauth2_time_now_sec();

	for (i = 0; i < impl->max_entries;
	     i++, OAUTH2_CACHE_SHM_ADD_OFFSET(ptr, impl)) {
		entry_key = (const char *)OAUTH2_CACHE_SHM_KEY_OFFSET(ptr);

		oauth2_trace2(log, "loop: %s", entry_key);

		if ((entry_key[0] != '\0') &&
		    (strncmp(entry_key, key, impl->max_key_size) == 0)) {

			oauth2_debug(log,
				     "found: %s (expires=" OAUTH2_TIME_T_FORMAT
				     ", now=" OAUTH2_TIME_T_FORMAT ")",
				     entry_key, ptr->expires_s, now_s);

			if (ptr->expires_s > now_s) {

				oauth2_debug(log, "not expired: %s", entry_key);

				ptr->access_s = now_s;
				*value = oauth2_strdup(
				    (const char *)OAUTH2_CACHE_SHM_VALUE_OFFSET(
					ptr, impl));

			} else {

				oauth2_debug(log, "expired, clean: %s",
					     entry_key);

				*OAUTH2_CACHE_SHM_KEY_OFFSET(ptr) = '\0';
				ptr->access_s = 0;
			}

			break;
		}
	}

	rc = true;

unlock:

	oauth2_ipc_mutex_unlock(log, impl->mutex);

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_shm_check_value(oauth2_log_t *log,
					 oauth2_cache_impl_shm_t *impl,
					 const char *value)
{
	bool rc = true;
	if ((value != NULL) && (strlen(value) > impl->max_val_size)) {
		oauth2_error(log,
			     "could not store value since value size is too "
			     "large (%lu > " OAUTH2_UINT_FORMAT ")",
			     (unsigned long)strlen(value),
			     (unsigned long)impl->max_val_size);
		rc = false;
	}
	return rc;
}

static bool oauth2_cache_shm_set(oauth2_log_t *log, oauth2_cache_t *cache,
				 const char *key, const char *value,
				 oauth2_time_t ttl_s)
{
	bool rc = false;
	oauth2_cache_shm_entry_t *match, *free, *lru;
	oauth2_cache_shm_entry_t *ptr;
	int i = 0;
	oauth2_time_t now_s, age_s = 0;
	oauth2_cache_impl_shm_t *impl = (oauth2_cache_impl_shm_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	if (oauth2_cache_shm_check_key(log, impl, key) == false)
		goto end;
	if (oauth2_cache_shm_check_value(log, impl, value) == false)
		goto end;

	if (oauth2_ipc_mutex_lock(log, impl->mutex) == false)
		goto end;

	ptr = oauth2_ipc_shm_get(log, impl->shm);
	if (ptr == NULL)
		goto unlock;

	now_s = oauth2_time_now_sec();

	match = NULL;
	free = NULL;
	lru = ptr;
	for (i = 0; i < impl->max_entries;
	     i++, OAUTH2_CACHE_SHM_ADD_OFFSET(ptr, impl)) {

		if (*OAUTH2_CACHE_SHM_KEY_OFFSET(ptr) == '\0') {
			if (free == NULL)
				free = ptr;
			continue;
		}

		if (strncmp((const char *)OAUTH2_CACHE_SHM_KEY_OFFSET(ptr), key,
			    impl->max_key_size) == 0) {
			match = ptr;
			break;
		}

		if (ptr->expires_s <= now_s) {
			if (free == NULL)
				free = ptr;
			continue;
		}

		if (ptr->access_s < lru->access_s) {
			lru = ptr;
		}
	}

	if (match == NULL && free == NULL) {
		age_s = (now_s - lru->access_s);
		// TODO: make this 1 hour warning window configurable?
		if (age_s < 3600) {
			oauth2_warn(
			    log,
			    "dropping LRU entry with age=" OAUTH2_TIME_T_FORMAT
			    " secs, which is less than one hour; consider "
			    "increasing the cache size through the setting for "
			    "the maximum number of cache entries that can be "
			    "held, which is " OAUTH2_UINT_FORMAT " now",
			    age_s, impl->max_entries);
		}
	}

	ptr = match ? match : (free ? free : lru);

	if (value != NULL) {

		/*
		memcpy((char *)OAUTH2_CACHE_SHM_KEY_OFFSET(ptr), key,
		strlen(key));
		((char *)OAUTH2_CACHE_SHM_KEY_OFFSET(ptr))[strlen(key)] = '\0';

		memcpy((char *)OAUTH2_CACHE_SHM_VALUE_OFFSET(ptr, impl), value,
		       strlen(value));
		((char *)OAUTH2_CACHE_SHM_VALUE_OFFSET(ptr,
		impl))[strlen(value)] =
		    '\0';
		*/
		oauth2_snprintf((char *)OAUTH2_CACHE_SHM_KEY_OFFSET(ptr),
				impl->max_key_size, "%s", key);
		oauth2_snprintf(
		    (char *)OAUTH2_CACHE_SHM_VALUE_OFFSET(ptr, impl),
		    impl->max_val_size, "%s", value);

		ptr->access_s = now_s;
		ptr->expires_s = now_s + ttl_s;

	} else {

		*OAUTH2_CACHE_SHM_KEY_OFFSET(ptr) = '\0';
		ptr->access_s = 0;
	}

	rc = true;

unlock:

	oauth2_ipc_mutex_unlock(log, impl->mutex);

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

OAUTH2_CACHE_TYPE_DECLARE(shm, false)
