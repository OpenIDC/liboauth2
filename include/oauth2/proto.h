#ifndef _OAUTH2_PROTO_H_
#define _OAUTH2_PROTO_H_

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

#include "oauth2/cfg.h"
#include "oauth2/http.h"

char *oauth2_get_source_token(oauth2_log_t *log, oauth2_cfg_source_token_t *cfg,
			      oauth2_http_request_t *request,
			      oauth2_cfg_server_callback_funcs_t *srv_cb,
			      void *srv_cb_ctx);

bool oauth2_ropc_exec(oauth2_log_t *log, oauth2_cfg_ropc_t *cfg,
		      const char *username, const char *password, char **rtoken,
		      oauth2_uint_t *status_code);

bool oauth2_cc_exec(oauth2_log_t *log, oauth2_cfg_cc_t *cfg, char **rtoken,
		    oauth2_uint_t *status_code);

#endif /* _OAUTH2_PROTO_H_ */
