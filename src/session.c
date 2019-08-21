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
#include "oauth2/mem.h"
#include "oauth2/util.h"
#include "util_int.h"

typedef struct oauth2_session_rec_t {
	char *user;
} oauth2_session_rec_t;

oauth2_session_rec_t *oauth2_session_rec_init(oauth2_log_t *log)
{
	oauth2_session_rec_t *s = (oauth2_session_rec_t *)oauth2_mem_alloc(
	    sizeof(oauth2_session_rec_t));
	s->user = NULL;
	return s;
}

oauth2_session_rec_t *oauth2_session_rec_clone(oauth2_log_t *log,
					       oauth2_session_rec_t *src)
{
	oauth2_session_rec_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_session_rec_init(log);
	dst->user = oauth2_strdup(src->user);

end:

	return dst;
}

void oauth2_session_rec_free(oauth2_log_t *log, oauth2_session_rec_t *s)
{
	if (s->user)
		oauth2_mem_free(s->user);
	if (s)
		oauth2_mem_free(s);
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(session, rec, user, char *, str)

bool oauth2_session_load(oauth2_log_t *log, const oauth2_openidc_cfg_t *c,
			 const oauth2_http_request_t *r,
			 oauth2_session_rec_t **session)
{
	bool rc = false;

	if (session == NULL)
		goto end;

	*session = oauth2_session_rec_init(log);

	if (*session == NULL)
		goto end;

	rc = true;

end:

	return rc;
}
