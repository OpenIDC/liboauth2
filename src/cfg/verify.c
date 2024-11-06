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
#include "oauth2/jose.h"
#include "oauth2/mem.h"

#include "cache_int.h"
#include "cfg_int.h"
#include "jose_int.h"
#include "oauth2_int.h"

#ifdef _WIN32
	int strcasecmp(const char *s1, const char *s2)
	{
		if (!s1)
			return (s1 == s2) ? 0 : 1;
		if (!s2)
			return 1;
		for (; tolower(*s1) == tolower(*s2); ++s1, ++s2)
			if (*s1 == 0)
				return 0;
		return tolower(*(const unsigned char *)s1) -
			   tolower(*(const unsigned char *)s2);
	}
#endif

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
	verify->type = OAUTH2_CFG_UINT_UNSET;
	verify->dpop.cache = NULL;
	verify->dpop.expiry_s = OAUTH2_CFG_UINT_UNSET;
	verify->dpop.iat_validate = OAUTH2_CFG_UINT_UNSET;
	verify->dpop.iat_slack_after = OAUTH2_CFG_UINT_UNSET;
	verify->dpop.iat_slack_before = OAUTH2_CFG_UINT_UNSET;
	verify->expiry_s = OAUTH2_CFG_UINT_UNSET;
	verify->mtls.env_var_name = NULL;
	verify->mtls.policy = OAUTH2_CFG_UINT_UNSET;
	verify->next = NULL;
	return verify;
}

void oauth2_cfg_token_verify_free(oauth2_log_t *log,
				  oauth2_cfg_token_verify_t *verify)
{
	oauth2_cfg_token_verify_t *ptr = verify;
	while (ptr) {
		verify = verify->next;
		if (ptr->mtls.env_var_name != NULL)
			oauth2_mem_free(ptr->mtls.env_var_name);
		if (ptr->ctx)
			oauth2_cfg_ctx_free(log, ptr->ctx);
		oauth2_mem_free(ptr);
		ptr = verify;
	}
}

oauth2_cfg_token_verify_t *
oauth2_cfg_token_verify_clone(oauth2_log_t *log,
			      const oauth2_cfg_token_verify_t *src)
{

	oauth2_cfg_token_verify_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_token_verify_init(NULL);
	dst->cache = src->cache;
	dst->expiry_s = src->expiry_s;
	dst->callback = src->callback;
	dst->type = src->type;
	dst->dpop.cache = src->dpop.cache;
	dst->dpop.expiry_s = src->dpop.expiry_s;
	dst->dpop.iat_slack_after = src->dpop.iat_slack_after;
	dst->dpop.iat_slack_before = src->dpop.iat_slack_before;
	dst->dpop.iat_validate = src->dpop.iat_validate;
	dst->mtls.env_var_name = oauth2_strdup(src->mtls.env_var_name);
	dst->mtls.policy = src->mtls.policy;
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

	v->cache = NULL;
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

static char *
_oauth2_cfg_token_verify_type_set(oauth2_log_t *log,
				  oauth2_cfg_token_verify_t *verify,
				  oauth2_nv_list_t *params)
{
	char *rv = NULL;
	const char *v = NULL;

	v = oauth2_nv_list_get(log, params, "type");

	if (v == NULL)
		goto end;

	if (strcasecmp(v, OAUTH2_TOKEN_VERIFY_BEARER_STR) == 0) {
		verify->type = OAUTH2_TOKEN_VERIFY_BEARER;
		goto end;
	}

	if (strcasecmp(v, OAUTH2_TOKEN_VERIFY_DPOP_STR) == 0) {
		verify->type = OAUTH2_TOKEN_VERIFY_DPOP;
		goto end;
	}

	if (strcasecmp(v, OAUTH2_TOKEN_VERIFY_MTLS_STR) == 0) {
		verify->type = OAUTH2_TOKEN_VERIFY_MTLS;
		goto end;
	}

	rv = oauth2_strdup("Invalid value, must be one of: \"");
	rv = oauth2_stradd(rv, OAUTH2_TOKEN_VERIFY_BEARER_STR, "\", \"", NULL);
	rv = oauth2_stradd(rv, OAUTH2_TOKEN_VERIFY_DPOP_STR, "\" or \"", NULL);
	rv = oauth2_stradd(rv, OAUTH2_TOKEN_VERIFY_MTLS_STR, "\".", NULL);

end:

	return rv;
}

#define OAUTH2_CFG_VERIFY_DPOP_CACHE_DEFAULT 10
#define OAUTH2_VERIFY_DPOP_SLACK_DEFAULT (oauth2_uint_t)5

static char *
_oauth2_cfg_token_verify_options_dpop_set(oauth2_log_t *log,
					  oauth2_cfg_token_verify_t *verify,
					  oauth2_nv_list_t *params)
{
	char *rv = NULL;

	verify->dpop.cache = oauth2_cache_obtain(
	    log, oauth2_nv_list_get(log, params, "dpop.cache"));

	verify->dpop.expiry_s = oauth2_parse_uint(
	    log, oauth2_nv_list_get(log, params, "dpop.expiry"),
	    OAUTH2_CFG_VERIFY_DPOP_CACHE_DEFAULT);

	verify->dpop.iat_validate = oauth2_parse_validate_claim_option(
	    log, oauth2_nv_list_get(log, params, "dpop.iat.verify"),
	    OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);

	verify->dpop.iat_slack_before = oauth2_parse_uint(
	    log, oauth2_nv_list_get(log, params, "dpop.iat.slack.before"),
	    OAUTH2_VERIFY_DPOP_SLACK_DEFAULT);

	verify->dpop.iat_slack_after = oauth2_parse_uint(
	    log, oauth2_nv_list_get(log, params, "dpop.iat.slack.after"),
	    OAUTH2_VERIFY_DPOP_SLACK_DEFAULT);

	return rv;
}

static char *
_oauth2_cfg_token_verify_options_mtls_set(oauth2_log_t *log,
					  oauth2_cfg_token_verify_t *verify,
					  oauth2_nv_list_t *params)
{
	char *rv = NULL;
	const char *policy = NULL;

	verify->mtls.env_var_name =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "mtls.env_var_name"));

	policy = oauth2_nv_list_get(log, params, "mtls.policy");
	if (policy != NULL) {
		if (strcmp(policy, "optional") == 0)
			verify->mtls.policy =
			    OAUTH2_MTLS_VERIFY_POLICY_OPTIONAL;
		else if (strcmp(policy, "required") == 0)
			verify->mtls.policy =
			    OAUTH2_MTLS_VERIFY_POLICY_REQUIRED;
	}
	return rv;
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

	v->cache = oauth2_cache_obtain(
	    log, oauth2_nv_list_get(log, params, "verify.cache"));
	v->expiry_s =
	    oauth2_parse_uint(log, oauth2_nv_list_get(log, params, "expiry"),
			      OAUTH2_CFG_VERIFY_RESULT_CACHE_DEFAULT);

	rv = _oauth2_cfg_token_verify_type_set(log, v, params);
	if (rv != NULL)
		goto end;

	if (v->type == OAUTH2_TOKEN_VERIFY_DPOP) {
		rv = _oauth2_cfg_token_verify_options_dpop_set(log, v, params);
		if (rv != NULL)
			goto end;
	} else if (v->type == OAUTH2_TOKEN_VERIFY_MTLS) {
		rv = _oauth2_cfg_token_verify_options_mtls_set(log, v, params);
		if (rv != NULL)
			goto end;
	}

	rv = oauth2_cfg_set_options(log, v, type, value, options,
				    _oauth2_cfg_verify_options_set);

end:

	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "leave: %s", rv ? rv : "(null)");

	return rv;
}
