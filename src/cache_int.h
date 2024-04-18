#ifndef _OAUTH2_CACHE_INT_H_
#define _OAUTH2_CACHE_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV - www.zmartzone.eu
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
