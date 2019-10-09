/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
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

oauth2_cfg_cache_t *oauth2_cfg_cache_init(oauth2_log_t *log)
{
	oauth2_cfg_cache_t *cache = NULL;
	cache =
	    (oauth2_cfg_cache_t *)oauth2_mem_alloc(sizeof(oauth2_cfg_cache_t));
	cache->cache = NULL;
	cache->expiry_s = OAUTH2_CFG_UINT_UNSET;
	return cache;
}

oauth2_cfg_cache_t *oauth2_cfg_cache_clone(oauth2_log_t *log,
					   oauth2_cfg_cache_t *src)
{
	oauth2_cfg_cache_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_cache_init(log);
	dst->cache = oauth2_cache_clone(log, src->cache);
	dst->expiry_s = src->expiry_s;

end:

	return dst;
}

void oauth2_cfg_cache_free(oauth2_log_t *log, oauth2_cfg_cache_t *cache)
{
	if (cache->cache)
		oauth2_cache_free(log, cache->cache);
	oauth2_mem_free(cache);
}

char *oauth2_cfg_cache_set_options(oauth2_log_t *log, oauth2_cfg_cache_t *cfg,
				   const char *prefix,
				   const oauth2_nv_list_t *params,
				   oauth2_uint_t default_expiry_s)
{
	char *rv = NULL;
	char *key = NULL;
	const char *type = NULL, *options = NULL;

	if (cfg == NULL) {
		rv = oauth2_strdup("internal error: cfg is null");
		goto end;
	}

	key = oauth2_stradd(NULL, prefix, ".cache", ".type");
	type = oauth2_nv_list_get(log, params, key);
	oauth2_mem_free(key);

	if ((type) && (strcmp(type, "none") == 0))
		goto end;

	key = oauth2_stradd(NULL, prefix, ".cache", ".options");
	options = oauth2_nv_list_get(log, params, key);
	oauth2_mem_free(key);

	cfg->cache = oauth2_cache_init(log, type, options);
	if (cfg->cache == NULL) {
		rv = oauth2_strdup(
		    "internal error: oauth2_cache_init returned null");
		goto end;
	}

	// TODO: have a separate verify_post_config function?
	if (oauth2_cache_post_config(log, cfg->cache) == false) {
		rv = oauth2_strdup(
		    "internal error: oauth2_cache_post_config returned false");
		goto end;
	}

	key = oauth2_stradd(NULL, prefix, ".cache", ".expiry");
	cfg->expiry_s = oauth2_parse_uint(
	    log, oauth2_nv_list_get(log, params, key), default_expiry_s);
	oauth2_mem_free(key);

end:

	return rv;
}
