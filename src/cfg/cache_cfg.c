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

#include "oauth2/mem.h"

#include "cfg_int.h"

char *oauth2_cfg_cache_set_options(oauth2_log_t *log, const char *type,
				   const oauth2_nv_list_t *params)
{
	char *rv = NULL;
	oauth2_cache_t *cache = NULL;

	cache = oauth2_cache_init(log, type, params);
	if (cache == NULL) {
		rv = oauth2_strdup(
		    "internal error: oauth2_cache_init returned null");
		goto end;
	}

	// TODO: have a separate verify_post_config function?
	if (oauth2_cache_post_config(log, cache) == false) {
		rv = oauth2_strdup(
		    "internal error: oauth2_cache_post_config returned false");
		goto end;
	}

end:

	return rv;
}
