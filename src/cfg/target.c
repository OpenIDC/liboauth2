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
#include "oauth2/mem.h"

#define OAUTH2_CFG_PASS_TARGET_AS_ENVVARS_DEFAULT true
#define OAUTH2_CFG_PASS_TARGET_AS_HEADERS_DEFAULT true

#define OAUTH2_CFG_PASS_TARGET_PREFIX_DEFAULT "OAUTH2_CLAIM_"
#define OAUTH2_CFG_PASS_TARGET_AUTHN_HEADER_DEFAULT NULL
#define OAUTH2_CFG_PASS_TARGET_REMOTE_USER_CLAIM_DEFAULT "sub"

typedef struct oauth2_cfg_target_pass_t {
	oauth2_flag_t as_envvars;
	oauth2_flag_t as_headers;
	char *authn_header;
	char *prefix;
	char *remote_user_claim;
} oauth2_cfg_target_pass_t;

oauth2_cfg_target_pass_t *oauth2_cfg_target_pass_init(oauth2_log_t *log)
{
	oauth2_cfg_target_pass_t *pass = NULL;

	pass = (oauth2_cfg_target_pass_t *)oauth2_mem_alloc(
	    sizeof(oauth2_cfg_target_pass_t));
	if (pass == NULL)
		goto end;

	pass->as_envvars = OAUTH2_CFG_FLAG_UNSET;
	pass->as_headers = OAUTH2_CFG_FLAG_UNSET;
	pass->authn_header = NULL;
	pass->prefix = NULL;
	pass->remote_user_claim = NULL;

end:

	return pass;
}

void oauth2_cfg_target_pass_free(oauth2_log_t *log,
				 oauth2_cfg_target_pass_t *pass)
{
	if (pass == NULL)
		goto end;

	if (pass->authn_header)
		oauth2_mem_free(pass->authn_header);
	if (pass->prefix)
		oauth2_mem_free(pass->prefix);
	if (pass->remote_user_claim)
		oauth2_mem_free(pass->remote_user_claim);
	oauth2_mem_free(pass);

end:

	return;
}

void oauth2_cfg_target_pass_merge(oauth2_log_t *log,
				  oauth2_cfg_target_pass_t *cfg,
				  oauth2_cfg_target_pass_t *base,
				  oauth2_cfg_target_pass_t *add)
{
	if ((cfg == NULL) || (base == NULL) || (add == NULL))
		goto end;

	cfg->as_envvars = add->as_envvars != OAUTH2_CFG_FLAG_UNSET
			      ? add->as_envvars
			      : base->as_envvars;
	cfg->as_headers = add->as_headers != OAUTH2_CFG_FLAG_UNSET
			      ? add->as_headers
			      : base->as_headers;
	cfg->authn_header = oauth2_strdup(
	    add->authn_header != NULL ? add->authn_header : base->authn_header);
	cfg->prefix =
	    oauth2_strdup(add->prefix != NULL ? add->prefix : base->prefix);
	cfg->remote_user_claim = oauth2_strdup(add->remote_user_claim != NULL
						   ? add->remote_user_claim
						   : base->remote_user_claim);

end:

	return;
}

char *oauth2_cfg_set_target_pass_options(oauth2_log_t *log,
					 oauth2_cfg_target_pass_t *cfg,
					 const char *options)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;
	const char *value = NULL;

	if (cfg == NULL) {
		rv = oauth2_strdup("struct is null");
		goto end;
	}

	if (oauth2_parse_form_encoded_params(log, options, &params) == false)
		goto end;

	value = oauth2_nv_list_get(log, params, "envvars");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_flag_slot(
		    cfg, offsetof(oauth2_cfg_target_pass_t, as_envvars),
		    value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "headers");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_flag_slot(
		    cfg, offsetof(oauth2_cfg_target_pass_t, as_headers),
		    value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "authn_header");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_target_pass_t, authn_header),
		    value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "prefix");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_target_pass_t, prefix), value));
		if (rv)
			goto end;
	}

	value = oauth2_nv_list_get(log, params, "remote_user_claim");
	if (value) {
		rv = oauth2_strdup(oauth2_cfg_set_str_slot(
		    cfg, offsetof(oauth2_cfg_target_pass_t, remote_user_claim),
		    value));
		if (rv)
			goto end;
	}

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

oauth2_flag_t
oauth2_cfg_target_pass_get_as_envvars(oauth2_cfg_target_pass_t *cfg)
{
	if (cfg->as_headers == OAUTH2_CFG_FLAG_UNSET)
		return OAUTH2_CFG_PASS_TARGET_AS_ENVVARS_DEFAULT;
	return cfg->as_envvars;
}

oauth2_flag_t
oauth2_cfg_target_pass_get_as_headers(oauth2_cfg_target_pass_t *cfg)
{
	if (cfg->as_headers == OAUTH2_CFG_FLAG_UNSET)
		return OAUTH2_CFG_PASS_TARGET_AS_HEADERS_DEFAULT;
	return cfg->as_headers;
}

const char *oauth2_cfg_target_pass_get_prefix(oauth2_cfg_target_pass_t *cfg)
{
	if (cfg->prefix == NULL)
		return OAUTH2_CFG_PASS_TARGET_PREFIX_DEFAULT;
	return cfg->prefix;
}

const char *
oauth2_cfg_target_pass_get_authn_header(oauth2_cfg_target_pass_t *cfg)
{
	if (cfg->authn_header == NULL)
		return OAUTH2_CFG_PASS_TARGET_AUTHN_HEADER_DEFAULT;
	return cfg->authn_header;
}

const char *
oauth2_cfg_target_get_remote_user_claim(oauth2_cfg_target_pass_t *cfg)
{
	if (cfg->remote_user_claim == NULL)
		return OAUTH2_CFG_PASS_TARGET_REMOTE_USER_CLAIM_DEFAULT;
	return cfg->remote_user_claim;
}
