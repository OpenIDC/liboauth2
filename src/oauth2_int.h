#ifndef _OAUTH2_INT_H_
#define _OAUTH2_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
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
#include "oauth2/log.h"
#include "oauth2/util.h"

#include "cfg_int.h"

_OAUTH_CFG_CTX_CALLBACK(oauth2_verify_options_set_introspect_url);
_OAUTH_CFG_CTX_CALLBACK(oauth2_verify_options_set_metadata_url);

bool oauth2_auth_basic(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
		       const oauth2_cfg_endpoint_auth_t *auth,
		       oauth2_nv_list_t *params);

bool oauth2_dpop_token_verify(oauth2_log_t *log,
			      oauth2_cfg_dpop_verify_t *verify,
			      oauth2_http_request_t *request,
			      const char *access_token, json_t *json_payload);

#endif /* _OAUTH2_INT_H_ */
