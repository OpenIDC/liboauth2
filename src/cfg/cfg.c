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
#include "oauth2/mem.h"

#include "cfg_int.h"
#include "util_int.h"

#include <errno.h>
#include <limits.h>

#define OAUTH2_CFG_FLAG_ON "on"
#define OAUTH2_CFG_FLAG_OFF "off"

static char *_crypto_passphrase = NULL;

const char *oauth2_crypto_passphrase_set(oauth2_log_t *log, void *dummy,
					 const char *passphrase)
{
	if (_crypto_passphrase != NULL)
		oauth2_mem_free(_crypto_passphrase);
	_crypto_passphrase = oauth2_strdup(passphrase);
	return NULL;
}

#define OAUTH2_CFG_DEFAULT_CRYPTO_PASSPHRASE_LEN 12

const char *oauth2_crypto_passphrase_get(oauth2_log_t *log)
{
	char *p = NULL;
	if (_crypto_passphrase == NULL) {
		oauth2_warn(log,
			    "no crypto passphrase configured, generating one: "
			    "configure it statically to survive restarts");
		p = oauth2_rand_str(log,
				    OAUTH2_CFG_DEFAULT_CRYPTO_PASSPHRASE_LEN);
		oauth2_crypto_passphrase_set(log, NULL, p);
		oauth2_mem_free(p);
	}
	return _crypto_passphrase;
}

const char *oauth2_cfg_set_flag_slot(void *cfg, size_t offset,
				     const char *value)
{
	const char *rv = NULL;
	oauth2_flag_t *fp = NULL;

	if (cfg == NULL) {
		rv = "internal error: struct is NULL";
		goto end;
	}

	if (value == NULL)
		goto end;

	fp = (oauth2_flag_t *)((char *)cfg + offset);

	if ((strcasecmp(value, OAUTH2_CFG_FLAG_ON) == 0) ||
	    (strcasecmp(value, "true") == 0) || (strcasecmp(value, "1") == 0))
		*fp = (oauth2_flag_t) true;
	else if ((strcasecmp(value, OAUTH2_CFG_FLAG_OFF) == 0) ||
		 (strcasecmp(value, "false") == 0) ||
		 (strcasecmp(value, "0") == 0)) {
		*fp = (oauth2_flag_t) false;
	} else
		rv =
		    "value must be \"true\", \"false\", \"1\", \"0\",  "
		    "\"" OAUTH2_CFG_FLAG_ON "\" or \"" OAUTH2_CFG_FLAG_OFF "\"";

end:

	return rv;
}

static const char *_oauth2_cfg_parse_long_uint(const char *value,
					       long int *rvalue)
{
	const char *rv = NULL;
	char *endptr = NULL;
	long int v = 0;

	if ((value == NULL) || (rvalue == NULL)) {
		rv = "internal error: value or rvalue is NULL";
		goto end;
	}

	errno = 0;
	v = strtol(value, &endptr, 10);

	if (endptr == value)
		rv = "strtol: no digits found";
	else if ((errno == ERANGE) && (v == LONG_MIN))
		rv = "strtol: underflow occurred";
	else if ((errno == ERANGE) && (v == LONG_MAX))
		rv = "strtol: overflow occurred";
	else if (errno == EINVAL)
		rv = "strtol: invalid, base contains unsupported value";
	else if ((errno != 0) && (v == 0))
		rv = "strtol: invalid, unspecified error occurred";
	else if ((errno == 0) && (*endptr != '\0'))
		rv = "strtol: valid, but additional characters remain";
	else if (v < 0) {
		rv = "strtol: negative value found";
	} else if ((errno == 0) && (*endptr == '\0')) {
		*rvalue = v;
	}

end:

	return rv;
}

const char *oauth2_cfg_set_uint_slot(void *cfg, size_t offset,
				     const char *value)
{
	const char *rv = NULL;
	oauth2_uint_t *fp = NULL;
	long int v = 0;

	if (cfg == NULL) {
		rv = "internal error: struct is NULL";
		goto end;
	}

	rv = _oauth2_cfg_parse_long_uint(value, &v);
	if (rv != NULL)
		goto end;

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

	if (cfg == NULL) {
		rv = "internal error: struct is NULL";
		goto end;
	}

	rv = _oauth2_cfg_parse_long_uint(value, &v);
	if (rv != NULL)
		goto end;

	fp = (oauth2_time_t *)((char *)cfg + offset);
	*fp = (oauth2_time_t)v;

end:

	return rv;
}

const char *oauth2_cfg_set_str_slot(void *cfg, size_t offset, const char *value)
{
	const char *rv = NULL;
	char **fp = NULL;

	if ((cfg == NULL) || (value == NULL)) {
		rv = "internal error: struct or value is NULL";
		goto end;
	}

	fp = (char **)((char *)cfg + offset);
	*fp = oauth2_strdup(value);
	if (*fp == NULL)
		rv = "oauth2_strdup() in oauth2_cfg_set_str_slot failed";

end:

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
		rv = oauth2_stradd(rv,
				   set[i + 1].type == NULL ? " or "
				   : i > 0		   ? ", "
							   : "",
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
