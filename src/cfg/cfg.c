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

#include "oauth2/cfg.h"
#include "oauth2/mem.h"

#include "cfg_int.h"
#include "util_int.h"

#include <limits.h>

#define OAUTH2_CFG_FLAG_ON "on"
#define OAUTH2_CFG_FLAG_OFF "off"

const char *oauth2_cfg_set_flag_slot(void *cfg, size_t offset,
				     const char *value)
{
	const char *rv = NULL;
	oauth2_flag_t *fp = NULL;

	fp = (oauth2_flag_t *)((char *)cfg + offset);

	if (strcasecmp(value, OAUTH2_CFG_FLAG_ON) == 0)
		*fp = 1;
	else if (strcasecmp(value, OAUTH2_CFG_FLAG_OFF) == 0)
		*fp = 0;
	else
		rv = "value must be \"" OAUTH2_CFG_FLAG_ON
		     "\" or \"" OAUTH2_CFG_FLAG_OFF "\"";

	return rv;
}

const char *oauth2_cfg_set_uint_slot(void *cfg, size_t offset,
				     const char *value)
{
	const char *rv = NULL;
	oauth2_uint_t *fp = NULL;
	long int v = 0;
	;

	v = strtol(value, NULL, 10);

	if (v == LONG_MIN) {
		rv = "strtol underflow";
		goto end;
	}
	if (v == LONG_MAX) {
		rv = "strtol overflow";
		goto end;
	}

	fp = (oauth2_uint_t *)((char *)cfg + offset);
	*fp = (oauth2_uint_t)v;

end:

	return rv;
}

const char *oauth2_cfg_set_time_slot(void *cfg, size_t offset,
				     const char *value)
{
	const char *rv = NULL;
	oauth2_time_t *fp = NULL;
	long int v = 0;
	;

	v = strtol(value, NULL, 10);

	if (v == LONG_MIN) {
		rv = "strtol underflow";
		goto end;
	}
	if (v == LONG_MAX) {
		rv = "strtol overflow";
		goto end;
	}

	fp = (oauth2_time_t *)((char *)cfg + offset);
	*fp = (oauth2_time_t)v;

end:

	return rv;
}

const char *oauth2_cfg_set_str_slot(void *cfg, size_t offset, const char *value)
{
	const char *rv = NULL;
	char **fp = NULL;

	fp = (char **)((char *)cfg + offset);
	*fp = oauth2_strdup(value);
	if (*fp == NULL)
		rv = "oauth2_strdup() in oauth2_cfg_set_str_slot failed";

	return rv;
}

oauth2_cfg_ctx_t *oauth2_cfg_ctx_init(oauth2_log_t *log)
{
	oauth2_cfg_ctx_t *ctx =
	    (oauth2_cfg_ctx_t *)oauth2_mem_alloc(sizeof(oauth2_cfg_ctx_t));
	ctx->ptr = NULL;
	ctx->callbacks = NULL;
	return ctx;
}

void oauth2_cfg_ctx_free(oauth2_log_t *log, oauth2_cfg_ctx_t *ctx)
{
	if (ctx == NULL)
		goto end;

	if (ctx->ptr)
		ctx->callbacks->free(log, ctx->ptr);

	oauth2_mem_free(ctx);

end:

	return;
}

oauth2_cfg_ctx_t *oauth2_cfg_ctx_clone(oauth2_log_t *log, oauth2_cfg_ctx_t *src)
{
	oauth2_cfg_ctx_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_ctx_init(NULL);
	dst->callbacks = src->callbacks;
	if (dst->callbacks)
		dst->ptr = dst->callbacks->clone(log, src->ptr);

end:

	return dst;
}

char *oauth2_cfg_set_options(oauth2_log_t *log, void *cfg, const char *type,
			     const char *value, const char *options,
			     const oauth2_cfg_set_options_ctx_t *set)
{
	char *rv = NULL;
	int i = 0;
	oauth2_nv_list_t *params = NULL;

	if (cfg == NULL)
		goto end;

	oauth2_debug(log, "enter: type=%s, value=%s, options=%s", type, value,
		     options);

	if (oauth2_parse_form_encoded_params(log, options, &params) == false)
		goto end;

	i = 0;
	while (set[i].type != NULL) {
		if (strcmp(set[i].type, type) == 0) {
			rv = set[i].set_options_callback(log, value, params,
							 cfg);
			goto end;
		}
		i++;
	}

	rv = oauth2_strdup("Invalid value, must be one of: ");
	i = 0;
	while (set[i].type != NULL) {
		rv = oauth2_stradd(
		    rv, set[i + 1].type == NULL ? " or " : i > 0 ? ", " : "",
		    set[i].type, NULL);
		i++;
	}
	rv = oauth2_stradd(rv, ".", NULL, NULL);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv ? rv : "(null)");

	return rv;
}
