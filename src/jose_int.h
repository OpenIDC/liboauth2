#ifndef _OAUTH2_JOSE_INT_H_
#define _OAUTH2_JOSE_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2023 - ZmartZone Holding BV - www.zmartzone.eu
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
#include "oauth2/log.h"
#include "oauth2/util.h"

#include "cfg_int.h"

typedef struct oauth2_jose_jwk_t {
	cjose_jwk_t *jwk;
	char *kid;
} oauth2_jose_jwk_t;

typedef struct oauth2_jose_jwk_list_t {
	oauth2_jose_jwk_t *jwk;
	struct oauth2_jose_jwk_list_t *next;
} oauth2_jose_jwk_list_t;

typedef struct oauth2_uri_ctx_t {
	oauth2_cfg_endpoint_t *endpoint;
	oauth2_cache_t *cache;
	oauth2_time_t expiry_s;
} oauth2_uri_ctx_t;

typedef enum oauth2_jose_jwks_provider_type_t {
	OAUTH2_JOSE_JWKS_PROVIDER_LIST,
	OAUTH2_JOSE_JWKS_PROVIDER_JWKS_URI,
	OAUTH2_JOSE_JWKS_PROVIDER_ECKEY_URI
} oauth2_jose_jwks_provider_type_t;

typedef struct oauth2_jose_jwks_provider_t oauth2_jose_jwks_provider_t;

typedef oauth2_jose_jwk_list_t *(oauth2_jose_jwks_resolve_cb_t)(
    oauth2_log_t *, oauth2_jose_jwks_provider_t *, bool *);

typedef struct oauth2_jose_jwks_provider_t {
	oauth2_jose_jwks_provider_type_t type;
	oauth2_jose_jwks_resolve_cb_t *resolve;
	union {
		oauth2_uri_ctx_t *jwks_uri;
		oauth2_jose_jwk_list_t *jwks;
	};
	// struct oauth2_jose_jwks_provider_t *next;
} oauth2_jose_jwks_provider_t;

_OAUTH2_CFG_CTX_TYPE_START(oauth2_jose_jwt_verify_ctx)
oauth2_jose_jwks_provider_t *jwks_provider;
char *issuer;
oauth2_jose_jwt_validate_claim_t iss_validate;
oauth2_jose_jwt_validate_claim_t exp_validate;
oauth2_jose_jwt_validate_claim_t iat_validate;
oauth2_uint_t iat_slack_before;
oauth2_uint_t iat_slack_after;
_OAUTH2_CFG_CTX_TYPE_END(oauth2_jose_jwt_verify_ctx)

void *oauth2_uri_ctx_init(oauth2_log_t *log);
void *oauth2_uri_ctx_clone(oauth2_log_t *log, void *c);
void oauth2_uri_ctx_free(oauth2_log_t *log, void *c);

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_plain);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_base64);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_base64url);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_hex);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_pem);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_pubkey);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_jwk);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_jwks_uri);
_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_eckey_uri);

char *oauth2_jose_resolve_from_uri(oauth2_log_t *log, oauth2_uri_ctx_t *uri_ctx,
				   bool *refresh);

char *oauth2_jose_options_uri_ctx(oauth2_log_t *log, const char *value,
				  const oauth2_nv_list_t *params,
				  oauth2_uri_ctx_t *ctx, const char *prefix);

void *oauth2_jose_jwt_verify_ctx_init(oauth2_log_t *log);
void *oauth2_jose_jwt_verify_ctx_clone(oauth2_log_t *log, void *s);
void oauth2_jose_jwt_verify_ctx_free(oauth2_log_t *log, void *c);

bool oauth2_jose_jwt_verify_set_options(
    oauth2_log_t *log, oauth2_jose_jwt_verify_ctx_t *jwt_verify,
    oauth2_jose_jwks_provider_type_t type, const oauth2_nv_list_t *params);

char *oauth2_jose_jwt_header_peek(oauth2_log_t *log,
				  const char *compact_encoded_jwt,
				  const char **alg);

bool oauth2_jose_jwt_validate_iat(oauth2_log_t *log, const json_t *json_payload,
				  oauth2_jose_jwt_validate_claim_t validate,
				  oauth2_uint_t slack_before,
				  oauth2_uint_t slack_after);

char *oauth2_jwt_create(oauth2_log_t *log, cjose_jwk_t *jwk, const char *alg,
			const char *iss, const char *sub, const char *client_id,
			const char *aud, oauth2_uint_t exp, bool include_iat,
			bool include_jti);

#endif /* _OAUTH2_JOSE_INT_H_ */
