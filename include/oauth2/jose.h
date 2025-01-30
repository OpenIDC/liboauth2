#ifndef _OAUTH2_JOSE_H_
#define _OAUTH2_JOSE_H_

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

#include <cjose/cjose.h>
#include <jansson.h>

#include "oauth2/cfg.h"
#include "oauth2/log.h"
#include "oauth2/util.h"

#define OAUTH2_JOSE_OPENSSL_ALG_SHA1 "sha1"
#define OAUTH2_JOSE_OPENSSL_ALG_SHA256 "sha256"

#define OAUTH2_JOSE_HDR_TYP "typ"
#define OAUTH2_JOSE_HDR_TYP_JWT "JWT"

#define OAUTH2_JOSE_JWT_ISS "iss"
#define OAUTH2_JOSE_JWT_IAT "iat"
#define OAUTH2_JOSE_JWT_EXP "exp"
#define OAUTH2_JOSE_JWT_SUB "sub"
#define OAUTH2_JOSE_JWT_AUD "aud"

typedef struct oauth2_jose_jwk_t oauth2_jose_jwk_t;
void oauth2_jose_jwk_release(oauth2_jose_jwk_t *jwk);

typedef struct oauth2_jose_jwk_list_t oauth2_jose_jwk_list_t;

void oauth2_jose_jwk_list_free(oauth2_log_t *log, oauth2_jose_jwk_list_t *keys);

bool oauth2_jose_hash_bytes(oauth2_log_t *log, const char *digest,
			    const unsigned char *src, unsigned int src_len,
			    unsigned char **dst, unsigned int *dst_len);
bool oauth2_jose_hash2s(oauth2_log_t *log, const char *digest, const char *src,
			char **dst);

bool oauth2_jose_jwk_create_symmetric(oauth2_log_t *log,
				      const char *client_secret,
				      const char *hash_algo,
				      oauth2_jose_jwk_t **jwk);

bool oauth2_jose_encrypt(oauth2_log_t *log, const char *secret,
			 const char *s_sig_payload, char **cser);
bool oauth2_jose_jwt_encrypt(oauth2_log_t *log, const char *secret,
			     json_t *payload, char **cser);
bool oauth2_jose_decrypt(oauth2_log_t *log, const char *secret,
			 const char *cser, char **result);
bool oauth2_jose_jwt_decrypt(oauth2_log_t *log, const char *secret,
			     const char *cser, json_t **result);

typedef struct oauth2_jose_jwt_verify_ctx_t oauth2_jose_jwt_verify_ctx_t;

bool oauth2_jose_jwt_verify(oauth2_log_t *log,
			    oauth2_jose_jwt_verify_ctx_t *jwt_verify_ctx,
			    const char *token, json_t **json_payload,
			    char **s_payload);

bool oauth2_jose_jwk_thumbprint(oauth2_log_t *log, const cjose_jwk_t *jwk,
				unsigned char **hash_bytes,
				unsigned int *hash_bytes_len);

char *oauth2_jwt_create(oauth2_log_t *log, cjose_jwk_t *jwk, const char *alg,
			const char *iss, const char *sub, const char *client_id,
			const char *aud, oauth2_uint_t exp, bool include_iat,
			bool include_jti, const json_t *json_payload);

#endif /* _OAUTH2_JOSE_H_ */
