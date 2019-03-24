#ifndef _OAUTH2_JOSE_INT_H_
#define _OAUTH2_JOSE_INT_H_

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
	char *uri;
	bool ssl_verify;
	oauth2_cfg_cache_t *cache;
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

typedef enum oauth2_jose_jwt_validate_claim_t {
	OAUTH2_JOSE_JWT_VALIDATE_CLAIM_OPTIONAL,
	OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED,
	OAUTH2_JOSE_JWT_VALIDATE_CLAIM_SKIP
} oauth2_jose_jwt_validate_claim_t;

typedef struct oauth2_jose_jwt_verify_ctx_t {
	oauth2_jose_jwks_provider_t *jwks_provider;
	oauth2_jose_jwt_validate_claim_t iss_validate;
	oauth2_jose_jwt_validate_claim_t exp_validate;
	oauth2_jose_jwt_validate_claim_t iat_validate;
	oauth2_uint_t iat_slack_before;
	oauth2_uint_t iat_slack_after;
} oauth2_jose_jwt_verify_ctx_t;

oauth2_uri_ctx_t *oauth2_uri_ctx_create(oauth2_log_t *log);
oauth2_uri_ctx_t *oauth2_uri_ctx_clone(oauth2_log_t *log,
				       oauth2_uri_ctx_t *src);
void oauth2_uri_ctx_free(oauth2_log_t *log, oauth2_uri_ctx_t *ctx);

char *
oauth2_jose_verify_options_jwk_set_plain(oauth2_log_t *log, const char *value,
					 const oauth2_nv_list_t *params,
					 oauth2_cfg_token_verify_t *verify);
char *
oauth2_jose_verify_options_jwk_set_base64(oauth2_log_t *log, const char *value,
					  const oauth2_nv_list_t *params,
					  oauth2_cfg_token_verify_t *verify);
char *oauth2_jose_verify_options_jwk_set_base64url(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    oauth2_cfg_token_verify_t *verify);
char *oauth2_jose_verify_options_jwk_set_hex(oauth2_log_t *log,
					     const char *value,
					     const oauth2_nv_list_t *params,
					     oauth2_cfg_token_verify_t *verify);
char *oauth2_jose_verify_options_jwk_set_pem(oauth2_log_t *log,
					     const char *value,
					     const oauth2_nv_list_t *params,
					     oauth2_cfg_token_verify_t *verify);
char *
oauth2_jose_verify_options_jwk_set_pubkey(oauth2_log_t *log, const char *value,
					  const oauth2_nv_list_t *params,
					  oauth2_cfg_token_verify_t *verify);
char *oauth2_jose_verify_options_jwk_set_jwk(oauth2_log_t *log,
					     const char *value,
					     const oauth2_nv_list_t *params,
					     oauth2_cfg_token_verify_t *verify);

char *oauth2_jose_resolve_from_uri(oauth2_log_t *log, oauth2_uri_ctx_t *uri_ctx,
				   bool *refresh);

char *oauth2_jose_options_uri_ctx(oauth2_log_t *log, const char *value,
				  const oauth2_nv_list_t *params,
				  oauth2_uri_ctx_t *ctx, const char *prefix);

char *oauth2_jose_verify_options_jwk_set_jwks_uri(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    oauth2_cfg_token_verify_t *verify);
char *oauth2_jose_verify_options_jwk_set_eckey_uri(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    oauth2_cfg_token_verify_t *verify);

void *oauth2_jose_jwt_verify_ctx_init(oauth2_log_t *log);
void *oauth2_jose_jwt_verify_ctx_clone(oauth2_log_t *log, void *s);
void oauth2_jose_jwt_verify_ctx_free(oauth2_log_t *log, void *c);

bool oauth2_jose_jwt_verify_set_options(
    oauth2_log_t *log, oauth2_jose_jwt_verify_ctx_t *jwt_verify,
    oauth2_jose_jwks_provider_type_t type, const oauth2_nv_list_t *params);

char *oauth2_jose_jwt_header_peek(oauth2_log_t *log,
				  const char *compact_encoded_jwt,
				  const char **alg);
bool oauth2_jose_jwt_verify(oauth2_log_t *log,
			    oauth2_jose_jwt_verify_ctx_t *jwt_verify_ctx,
			    const char *token, json_t **json_payload,
			    char **s_payload);

#endif /* _OAUTH2_JOSE_INT_H_ */
