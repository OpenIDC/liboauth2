#ifndef _OAUTH2_JOSE_H_
#define _OAUTH2_JOSE_H_

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

#include <cjose/cjose.h>
#include <jansson.h>

#include "oauth2/cfg.h"
#include "oauth2/log.h"
#include "oauth2/util.h"

#define OAUTH2_JOSE_OPENSSL_ALG_SHA1 "sha1"
#define OAUTH2_JOSE_OPENSSL_ALG_SHA256 "sha256"

#define OAUTH2_JOSE_JWT_ISS "iss"
#define OAUTH2_JOSE_JWT_IAT "iat"
#define OAUTH2_JOSE_JWT_EXP "exp"

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

bool oauth2_jose_jwt_encrypt(oauth2_log_t *log, const char *secret,
			     json_t *payload, char **cser);
bool oauth2_jose_jwt_decrypt(oauth2_log_t *log, const char *secret,
			     const char *cser, json_t **result);

#endif /* _OAUTH2_JOSE_H_ */
