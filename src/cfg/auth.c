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
#include "oauth2/mem.h"

#include "cfg_int.h"

#include <cjose/cjose.h>

#define OAUTH2_ENDPOINT_AUTH_NONE_STR "none"
#define OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR "client_secret_basic"
#define OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR "client_secret_post"
#define OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR "client_secret_jwt"
#define OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR "private_key_jwt"
#define OAUTH2_ENDPOINT_AUTH_CLIENT_CERT_STR "client_cert"
#define OAUTH2_ENDPOINT_AUTH_BASIC_STR "basic"

oauth2_cfg_endpoint_auth_t *oauth2_cfg_endpoint_auth_init(oauth2_log_t *log)
{
	oauth2_cfg_endpoint_auth_t *auth =
	    (oauth2_cfg_endpoint_auth_t *)oauth2_mem_alloc(
		sizeof(oauth2_cfg_endpoint_auth_t));
	auth->type = OAUTH2_ENDPOINT_AUTH_NONE;
	return auth;
}

void oauth2_cfg_endpoint_auth_free(oauth2_log_t *log,
				   oauth2_cfg_endpoint_auth_t *auth)
{
	if (auth == NULL)
		goto end;

	switch (auth->type) {
	case OAUTH2_ENDPOINT_AUTH_NONE:
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC:
		if (auth->client_secret_basic.client_id)
			oauth2_mem_free(auth->client_secret_basic.client_id);
		if (auth->client_secret_basic.client_secret)
			oauth2_mem_free(
			    auth->client_secret_basic.client_secret);
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST:
		if (auth->client_secret_post.client_id)
			oauth2_mem_free(auth->client_secret_post.client_id);
		if (auth->client_secret_post.client_secret)
			oauth2_mem_free(auth->client_secret_post.client_secret);
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT:
		if (auth->client_secret_jwt.client_id)
			oauth2_mem_free(auth->client_secret_jwt.client_id);
		if (auth->client_secret_jwt.jwk)
			cjose_jwk_release(auth->client_secret_jwt.jwk);
		if (auth->client_secret_jwt.aud)
			oauth2_mem_free(auth->client_secret_jwt.aud);
		break;
	case OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT:
		if (auth->private_key_jwt.client_id)
			oauth2_mem_free(auth->private_key_jwt.client_id);
		if (auth->private_key_jwt.jwk)
			cjose_jwk_release(auth->private_key_jwt.jwk);
		if (auth->private_key_jwt.aud)
			oauth2_mem_free(auth->private_key_jwt.aud);
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_CERT:
		if (auth->client_cert.certfile)
			oauth2_mem_free(auth->client_cert.certfile);
		if (auth->client_cert.keyfile)
			oauth2_mem_free(auth->client_cert.keyfile);
		break;
	case OAUTH2_ENDPOINT_AUTH_BASIC:
		if (auth->basic.username)
			oauth2_mem_free(auth->basic.username);
		if (auth->basic.password)
			oauth2_mem_free(auth->basic.password);
		break;
	}

	oauth2_mem_free(auth);

end:

	return;
}

oauth2_cfg_endpoint_auth_t *
oauth2_cfg_endpoint_auth_clone(oauth2_log_t *log,
			       const oauth2_cfg_endpoint_auth_t *src)
{
	oauth2_cfg_endpoint_auth_t *dst = NULL;
	cjose_err err;

	if (src == NULL)
		goto end;

	dst = oauth2_cfg_endpoint_auth_init(log);
	dst->type = src->type;
	switch (dst->type) {
	case OAUTH2_ENDPOINT_AUTH_NONE:
		dst->none = src->none;
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC:
		dst->client_secret_basic.client_id =
		    oauth2_strdup(src->client_secret_basic.client_id);
		dst->client_secret_basic.client_secret =
		    oauth2_strdup(src->client_secret_basic.client_secret);
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST:
		dst->client_secret_post.client_id =
		    oauth2_strdup(src->client_secret_post.client_id);
		dst->client_secret_post.client_secret =
		    oauth2_strdup(src->client_secret_post.client_secret);
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT:
		dst->client_secret_jwt.aud =
		    oauth2_strdup(src->client_secret_jwt.aud);
		dst->client_secret_jwt.client_id =
		    oauth2_strdup(src->client_secret_jwt.client_id);
		dst->client_secret_jwt.jwk =
		    cjose_jwk_retain(src->client_secret_jwt.jwk, &err);
		break;
	case OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT:
		dst->private_key_jwt.aud =
		    oauth2_strdup(src->private_key_jwt.aud);
		dst->private_key_jwt.client_id =
		    oauth2_strdup(src->private_key_jwt.client_id);
		dst->private_key_jwt.jwk =
		    cjose_jwk_retain(src->private_key_jwt.jwk, &err);
		break;
	case OAUTH2_ENDPOINT_AUTH_CLIENT_CERT:
		dst->client_cert.certfile =
		    oauth2_strdup(src->client_cert.certfile);
		dst->client_cert.keyfile =
		    oauth2_strdup(src->client_cert.keyfile);
		break;
	case OAUTH2_ENDPOINT_AUTH_BASIC:
		dst->basic.username = oauth2_strdup(src->basic.username);
		dst->basic.password = oauth2_strdup(src->basic.password);
		break;
	}

end:

	return dst;
}

static char *
oauth2_cfg_endpoint_auth_none_options_set(oauth2_log_t *log,
					  oauth2_cfg_endpoint_auth_t *auth,
					  const oauth2_nv_list_t *params)
{
	auth->type = OAUTH2_ENDPOINT_AUTH_NONE;
	return NULL;
}

static char *oauth2_cfg_endpoint_auth_client_secret_basic_options_set(
    oauth2_log_t *log, oauth2_cfg_endpoint_auth_t *auth,
    const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	auth->type = OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC;

	auth->client_secret_basic.client_id =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_id"));
	if (auth->client_secret_basic.client_id == NULL) {
		rv =
		    oauth2_stradd(NULL, "client_id", " must be set for ",
				  OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR);
		goto end;
	}

	auth->client_secret_basic.client_secret =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_secret"));
	if (auth->client_secret_basic.client_secret == NULL) {
		rv =
		    oauth2_stradd(NULL, "client_secret", " must be set for ",
				  OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR);
		goto end;
	}

end:

	return rv;
}

static char *oauth2_cfg_endpoint_auth_client_secret_post_options_set(
    oauth2_log_t *log, oauth2_cfg_endpoint_auth_t *auth,
    const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	auth->type = OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST;

	auth->client_secret_post.client_id =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_id"));
	if (auth->client_secret_post.client_id == NULL) {
		rv = oauth2_stradd(NULL, "client_id", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR);
		goto end;
	}

	auth->client_secret_post.client_secret =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_secret"));
	if (auth->client_secret_post.client_secret == NULL) {
		rv = oauth2_stradd(NULL, "client_secret", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR);
		goto end;
	}

end:

	return rv;
}

static char *oauth2_cfg_endpoint_auth_client_secret_jwt_options_set(
    oauth2_log_t *log, oauth2_cfg_endpoint_auth_t *auth,
    const oauth2_nv_list_t *params)
{
	char *rv = NULL;
	const char *client_secret = NULL;
	cjose_err err;

	auth->type = OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT;

	auth->client_secret_jwt.client_id =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_id"));
	if (auth->client_secret_jwt.client_id == NULL) {
		rv = oauth2_stradd(NULL, "client_id", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR);
		goto end;
	}

	client_secret = oauth2_nv_list_get(log, params, "client_secret");
	if (client_secret == NULL) {
		rv = oauth2_stradd(NULL, "client_secret", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR);
		goto end;
	}

	err.code = CJOSE_ERR_NONE;
	auth->client_secret_jwt.jwk = cjose_jwk_create_oct_spec(
	    (const unsigned char *)client_secret, strlen(client_secret), &err);
	if (auth->client_secret_jwt.jwk == NULL) {
		rv = oauth2_stradd(NULL, "cjose_jwk_create_oct_spec failed: ",
				   err.message, NULL);
		goto end;
	}

	//	auth->client_secret_jwt.client_secret =
	// oauth2_strdup(oauth2_nv_list_get(log, params, "client_secret"));
	// if
	//(auth->client_secret_jwt.client_secret == NULL) { 		rv =
	// oauth2_stradd(NULL, "client_secret", " must be set for ",
	// OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR); 		goto
	// end;
	//	}

	auth->client_secret_jwt.aud =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "aud"));
	if (auth->client_secret_jwt.aud == NULL) {
		rv = oauth2_stradd(NULL, "aud", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR);
		goto end;
	}

end:

	return rv;
}

static char *oauth2_cfg_endpoint_auth_private_key_jwt_options_set(
    oauth2_log_t *log, oauth2_cfg_endpoint_auth_t *auth,
    const oauth2_nv_list_t *params)
{
	char *rv = NULL;
	const char *jwk = NULL;
	cjose_err err;

	auth->type = OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT;

	auth->private_key_jwt.client_id =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_id"));
	if (auth->private_key_jwt.client_id == NULL) {
		rv = oauth2_stradd(NULL, "client_id", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR);
		goto end;
	}

	err.code = CJOSE_ERR_NONE;
	jwk = oauth2_nv_list_get(log, params, "jwk");
	if (jwk == NULL) {
		rv = oauth2_stradd(NULL, "jwk", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR);
		goto end;
	}

	auth->private_key_jwt.jwk = cjose_jwk_import(jwk, strlen(jwk), &err);
	if (auth->private_key_jwt.jwk == NULL) {
		rv = oauth2_stradd(NULL, "parsing JWK failed: ",
				   "cjose_jws_import error: ", err.message);
		goto end;
	}

	auth->private_key_jwt.aud =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "aud"));
	if (auth->private_key_jwt.aud == NULL) {
		rv = oauth2_stradd(NULL, "aud", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR);
		goto end;
	}

end:

	return rv;
}

static char *oauth2_cfg_endpoint_auth_client_cert_options_set(
    oauth2_log_t *log, oauth2_cfg_endpoint_auth_t *auth,
    const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	auth->type = OAUTH2_ENDPOINT_AUTH_CLIENT_CERT;

	auth->client_cert.certfile =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "cert"));
	if (auth->client_cert.certfile == NULL) {
		rv = oauth2_stradd(NULL, "cert", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_CLIENT_CERT_STR);
		goto end;
	}

	auth->client_cert.keyfile =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "key"));
	if (auth->client_cert.keyfile == NULL) {
		rv = oauth2_stradd(NULL, "key", " must be set for ",
				   OAUTH2_ENDPOINT_AUTH_CLIENT_CERT_STR);
		goto end;
	}

end:

	return rv;
}

static char *
oauth2_cfg_endpoint_auth_basic_options_set(oauth2_log_t *log,
					   oauth2_cfg_endpoint_auth_t *auth,
					   const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	auth->type = OAUTH2_ENDPOINT_AUTH_BASIC;

	auth->basic.username =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "username"));
	auth->basic.password =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "password"));

	return rv;
}

typedef char *(oauth2_cfg_endpoint_auth_set_options_cb_t)(
    oauth2_log_t *log, oauth2_cfg_endpoint_auth_t *auth,
    const oauth2_nv_list_t *params);

typedef struct oauth2_cfg_endpoint_auth_set_options_ctx_t {
	const char *type;
	oauth2_cfg_endpoint_auth_set_options_cb_t *options_callback;
} oauth2_cfg_endpoint_auth_set_options_ctx_t;

// clang-format off
static oauth2_cfg_endpoint_auth_set_options_ctx_t _oauth2_cfg_endpoint_auth_options_set[] = {
	{ OAUTH2_ENDPOINT_AUTH_NONE_STR,				oauth2_cfg_endpoint_auth_none_options_set 					},
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR,	oauth2_cfg_endpoint_auth_client_secret_basic_options_set	},
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR,	oauth2_cfg_endpoint_auth_client_secret_post_options_set		},
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR,	oauth2_cfg_endpoint_auth_client_secret_jwt_options_set		},
	{ OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR,		oauth2_cfg_endpoint_auth_private_key_jwt_options_set		},
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_CERT_STR,			oauth2_cfg_endpoint_auth_client_cert_options_set			},
	{ OAUTH2_ENDPOINT_AUTH_BASIC_STR,				oauth2_cfg_endpoint_auth_basic_options_set					},
	{ NULL,											NULL 														}
};
// clang-format on

char *oauth2_cfg_set_endpoint_auth(oauth2_log_t *log,
				   oauth2_cfg_endpoint_auth_t *auth,
				   const char *type,
				   const oauth2_nv_list_t *params,
				   const char *prefix)
{
	char *rv = NULL;
	int i = 0;

	if (auth == NULL) {
		rv = oauth2_strdup("internal error: auth must be set");
		goto end;
	}

	if (type == NULL)
		goto end;

	i = 0;
	while (_oauth2_cfg_endpoint_auth_options_set[i].type != NULL) {
		if (strcmp(_oauth2_cfg_endpoint_auth_options_set[i].type,
			   type) == 0) {
			rv = _oauth2_cfg_endpoint_auth_options_set[i]
				 .options_callback(log, auth, params);
			goto end;
		}
		i++;
	}

	rv = oauth2_strdup("Invalid value, must be one of: ");
	i = 0;
	while (_oauth2_cfg_endpoint_auth_options_set[i].type != NULL) {
		rv = oauth2_stradd(
		    rv,
		    _oauth2_cfg_endpoint_auth_options_set[i + 1].type == NULL
			? " or "
			: i > 0 ? ", " : "",
		    _oauth2_cfg_endpoint_auth_options_set[i].type, NULL);
		i++;
	}
	rv = oauth2_stradd(rv, ".", NULL, NULL);

end:

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

oauth2_cfg_endpoint_auth_type_t
oauth2_cfg_endpoint_auth_type(const oauth2_cfg_endpoint_auth_t *auth)
{
	return auth ? auth->type : OAUTH2_ENDPOINT_AUTH_NONE;
}
