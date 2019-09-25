#ifndef _OAUTH2_SESSION_H_
#define _OAUTH2_SESSION_H_

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

#include "oauth2/openidc.h"
#include "oauth2/util.h"

typedef struct oauth2_session_rec_t oauth2_session_rec_t;

OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(session, rec, user, char *)
OAUTH2_TYPE_DECLARE_MEMBER_GET(session, rec, id_token_claims, json_t *)
bool oauth2_session_rec_id_token_claims_set(oauth2_log_t *log,
					    oauth2_session_rec_t *session,
					    json_t *id_token);

bool oauth2_session_load(oauth2_log_t *log, const oauth2_cfg_openidc_t *c,
			 oauth2_http_request_t *r,
			 oauth2_session_rec_t **session);
bool oauth2_session_save(oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
			 const oauth2_http_request_t *request,
			 oauth2_http_response_t *response,
			 oauth2_session_rec_t *session);
void oauth2_session_rec_free(oauth2_log_t *log, oauth2_session_rec_t *s);

#endif /* _OAUTH2_SESSION_H_ */