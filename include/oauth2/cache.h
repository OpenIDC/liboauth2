#ifndef _OAUTH2_CACHE_H_
#define _OAUTH2_CACHE_H_

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

#include "oauth2/log.h"
#include "oauth2/util.h"

typedef struct oauth2_cache_t oauth2_cache_t;

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

oauth2_cache_t *oauth2_cache_obtain(oauth2_log_t *log, const char *name);

bool oauth2_cache_get(oauth2_log_t *log, oauth2_cache_t *ctx, const char *key,
		      char **value);
bool oauth2_cache_set(oauth2_log_t *log, oauth2_cache_t *ctx, const char *key,
		      const char *value, oauth2_time_t ttl_s);

#endif /* _OAUTH2_CACHE_H_ */
