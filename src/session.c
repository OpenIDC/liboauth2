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

#include "oauth2/session.h"
/*
#include "oauth2/mem.h"
#include "oauth2/util.h"
#include "util_int.h"

#include <string.h>
*/

typedef struct oauth2_session_rec_t {
	const char *user;
} oauth2_session_rec_t;

bool oauth2_session_load(oauth2_log_t *log, const oauth2_openidc_cfg_t *c,
			 const oauth2_http_request_t *r,
			 oauth2_session_rec_t **session)
{
	bool rc = false;

	goto end;

end:

	return rc;
}
