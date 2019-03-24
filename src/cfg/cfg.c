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

#include "oauth2/cfg.h"

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
