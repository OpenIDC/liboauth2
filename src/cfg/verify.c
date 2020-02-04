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
#include "oauth2/jose.h"
#include "oauth2/mem.h"

#include "cfg_int.h"
#include "jose_int.h"
#include "oauth2_int.h"

#define OAUTH2_JOSE_VERIFY_JWK_PLAIN_STR "plain"
#define OAUTH2_JOSE_VERIFY_JWK_BASE64_STR "base64"
#define OAUTH2_JOSE_VERIFY_JWK_BASE64URL_STR "base64url"
#define OAUTH2_JOSE_VERIFY_JWK_HEX_STR "hex"
#define OAUTH2_JOSE_VERIFY_JWK_PEM_STR "pem"
#define OAUTH2_JOSE_VERIFY_JWK_PUBKEY_STR "pubkey"
#define OAUTH2_JOSE_VERIFY_JWK_JWK_STR "jwk"
#define OAUTH2_JOSE_VERIFY_JWK_JWKS_URI_STR "jwks_uri"
#define OAUTH2_JOSE_VERIFY_JWK_ECKEY_URI_STR "eckey_uri"
#define OAUTH2_CFG_VERIFY_INTROSPECT_URL_STR "introspect"
#define OAUTH2_CFG_VERIFY_METADATA_URL_STR "metadata"

// clang-format off
static oauth2_cfg_set_options_ctx_t _oauth2_cfg_verify_options_set[] = {
	{ OAUTH2_JOSE_VERIFY_JWK_PLAIN_STR, oauth2_jose_verify_options_jwk_set_plain },
	{ OAUTH2_JOSE_VERIFY_JWK_BASE64_STR, oauth2_jose_verify_options_jwk_set_base64 },
	{ OAUTH2_JOSE_VERIFY_JWK_BASE64URL_STR, oauth2_jose_verify_options_jwk_set_base64url },
	{ OAUTH2_JOSE_VERIFY_JWK_HEX_STR, oauth2_jose_verify_options_jwk_set_hex },
	{ OAUTH2_JOSE_VERIFY_JWK_PEM_STR, oauth2_jose_verify_options_jwk_set_pem },
	{ OAUTH2_JOSE_VERIFY_JWK_PUBKEY_STR, oauth2_jose_verify_options_jwk_set_pubkey },
	{ OAUTH2_JOSE_VERIFY_JWK_JWK_STR, oauth2_jose_verify_options_jwk_set_jwk },
	{ OAUTH2_JOSE_VERIFY_JWK_JWKS_URI_STR, oauth2_jose_verify_options_jwk_set_jwks_uri },
	{ OAUTH2_JOSE_VERIFY_JWK_ECKEY_URI_STR, oauth2_jose_verify_options_jwk_set_eckey_uri },
	{ OAUTH2_CFG_VERIFY_INTROSPECT_URL_STR, oauth2_verify_options_set_introspect_url },
	{ OAUTH2_CFG_VERIFY_METADATA_URL_STR, oauth2_verify_options_set_metadata_url },
	{ NULL, NULL }
};
// clang-format on

oauth2_cfg_token_verify_t *oauth2_cfg_token_verify_init(oauth2_log_t *log)
{
	oauth2_cfg_token_verify_t *verify =
	    (oauth2_cfg_token_verify_t *)oauth2_mem_alloc(
		sizeof(oauth2_cfg_token_verify_t));
	verify->ctx = NULL;
	verify->callback = NULL;
	verify->cache = NULL;
	verify->next = NULL;
	return verify;
}

void oauth2_cfg_token_verify_free(oauth2_log_t *log,
				  oauth2_cfg_token_verify_t *verify)
{
	oauth2_cfg_token_verify_t *ptr = verify;
	while (ptr) {
		verify = verify->next;
		if (ptr->cache)
			oauth2_cfg_cache_free(log, ptr->cache);
		if (ptr->ctx)
			oauth2_cfg_ctx_free(log, ptr->ctx);
		oauth2_mem_free(ptr);
		ptr = verify;
	}
}

oauth2_cfg_token_verify_t *
oauth2_cfg_token_verify_clone(oauth2_log_t *log, oauth2_cfg_token_verify_t *src)
{

	oauth2_cfg_token_verify_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_token_verify_init(NULL);
	dst->cache = oauth2_cfg_cache_clone(log, src->cache);
	dst->callback = src->callback;
	dst->ctx = oauth2_cfg_ctx_clone(log, src->ctx);
	dst->next = oauth2_cfg_token_verify_clone(NULL, src->next);

end:

	return dst;
}

static oauth2_cfg_token_verify_t *
_oauth2_cfg_token_verify_add(oauth2_log_t *log,
			     oauth2_cfg_token_verify_t **verify)
{
	oauth2_cfg_token_verify_t *v = NULL, *last = NULL;

	if (verify == NULL)
		goto end;

	v = oauth2_cfg_token_verify_init(log);
	if (v == NULL)
		goto end;

	v->cache = oauth2_cfg_cache_init(log);
	v->callback = NULL;
	v->ctx = oauth2_cfg_ctx_init(log);
	if (v->ctx == NULL)
		goto end;

	if (*verify == NULL) {
		*verify = v;
		goto end;
	}

	for (last = *verify; last->next; last = last->next)
		;
	last->next = v;

end:

	return v;
}

#define OAUTH2_CFG_VERIFY_RESULT_CACHE_DEFAULT 300

char *oauth2_cfg_token_verify_add_options(oauth2_log_t *log,
					  oauth2_cfg_token_verify_t **verify,
					  const char *type, const char *value,
					  const char *options)
{
	char *rv = NULL;
	oauth2_cfg_token_verify_t *v = NULL;

	oauth2_nv_list_t *params = NULL;

	oauth2_debug(log, "enter: type=%s, value=%s, options=%s", type, value,
		     options);

	if (oauth2_parse_form_encoded_params(log, options, &params) == false)
		goto end;

	v = _oauth2_cfg_token_verify_add(log, verify);

	rv = oauth2_cfg_set_options(log, v, type, value, options,
				    _oauth2_cfg_verify_options_set);

	oauth2_cfg_cache_set_options(log, v->cache, "verify", params,
				     OAUTH2_CFG_VERIFY_RESULT_CACHE_DEFAULT);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv ? rv : "(null)");

	return rv;
}
