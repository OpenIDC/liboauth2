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

#include "oauth2/mem.h"

#include "cache_int.h"
#include "cfg_int.h"

char *oauth2_cfg_set_cache(oauth2_log_t *log, void *dummy, const char *type,
			   const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;
	oauth2_cache_t *cache = NULL;

	if (oauth2_parse_form_encoded_params(log, options, &params) == false) {
		rv = "parsing cache parameters failed";
		goto end;
	}

	cache = _oauth2_cache_init(log, type, params);
	if (cache == NULL) {
		rv = oauth2_strdup(
		    "internal error: oauth2_cache_init returned null");
		goto end;
	}

	if (_oauth2_cache_post_config(log, cache) == false) {
		rv = oauth2_strdup(
		    "internal error: oauth2_cache_post_config returned false");
		goto end;
	}

end:

	if (params)
		oauth2_nv_list_free(log, params);

	return rv;
}
