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
