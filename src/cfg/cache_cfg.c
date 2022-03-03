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
