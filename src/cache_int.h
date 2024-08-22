#ifndef _OAUTH2_CACHE_INT_H_
#define _OAUTH2_CACHE_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
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

#include "oauth2/cache.h"
#include "oauth2/log.h"

typedef struct oauth2_cache_t {
	void *impl;
	oauth2_cache_type_t *type;
	char *key_hash_algo;
	bool encrypt;
	char *enc_key;
	char *passphrase_hash_algo;
} oauth2_cache_t;

oauth2_cache_t *_oauth2_cache_init(oauth2_log_t *log, const char *type,
				   const oauth2_nv_list_t *params);
bool _oauth2_cache_post_config(oauth2_log_t *log, oauth2_cache_t *cache);
bool _oauth2_cache_child_init(oauth2_log_t *log, oauth2_cache_t *cache);

void _oauth2_cache_global_cleanup(oauth2_log_t *log);

// clang-format off
#define OAUTH2_CACHE_TYPE_DECLARE(type, encrypt)	\
	oauth2_cache_type_t oauth2_cache_##type = {		\
		#type,									\
		encrypt,								\
		oauth2_cache_##type##_init,				\
		oauth2_cache_##type##_post_config,			\
		oauth2_cache_##type##_child_init,			\
		oauth2_cache_##type##_get,					\
		oauth2_cache_##type##_set,					\
		oauth2_cache_##type##_free					\
	};
// clang-format on

#endif /* _OAUTH2_CACHE_INT_H_ */
