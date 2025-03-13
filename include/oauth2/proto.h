#ifndef _OAUTH2_PROTO_H_
#define _OAUTH2_PROTO_H_

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
