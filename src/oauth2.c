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

#include "oauth2/oauth2.h"
#include "cfg_int.h"
#include "oauth2/cfg.h"
#include "oauth2/http.h"
#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include "jose_int.h"
#include "util_int.h"

#include <cjose/cjose.h>

/*
 * auth
 */

#define OAUTH2_CLAIM_ISS "iss"
#define OAUTH2_CLAIM_SUB "sub"
#define OAUTH2_CLAIM_JTI "jti"
#define OAUTH2_CLAIM_EXP "exp"
#define OAUTH2_CLAIM_AUD "aud"
#define OAUTH2_CLAIM_IAT "iat"

#define OAUTH2_CLIENT_ASSERTION "client_assertion"
#define OAUTH2_CLIENT_ASSERTION_TYPE "client_assertion_type"
#define OAUTH2_CLIENT_ASSERTION_TYPE_JWT_BEARER                                \
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#define OAUTH2_JTI_LENGTH 16

static bool _oauth2_add_signed_jwt(oauth2_log_t *log, cjose_jwk_t *jwk,
				   const char *alg, const char *client_id,
				   const char *aud, oauth2_nv_list_t *params)
{

	bool rc = false;
	char *payload = NULL;
	json_t *assertion = NULL;
	cjose_header_t *hdr = NULL;
	cjose_jws_t *jws = NULL;
	const char *jwt = NULL;
	cjose_err err;
	char *jti = NULL;

	oauth2_debug(log, "enter");

	assertion = json_object();
	jti = oauth2_rand_str(log, OAUTH2_JTI_LENGTH);
	json_object_set_new(assertion, OAUTH2_CLAIM_JTI, json_string(jti));
	json_object_set_new(assertion, OAUTH2_CLAIM_ISS,
			    json_string(client_id));
	json_object_set_new(assertion, OAUTH2_CLAIM_SUB,
			    json_string(client_id));
	json_object_set_new(assertion, OAUTH2_CLAIM_AUD, json_string(aud));
	json_object_set_new(assertion, OAUTH2_CLAIM_EXP,
			    json_integer(oauth2_time_now_sec() + 60));
	json_object_set_new(assertion, OAUTH2_CLAIM_IAT,
			    json_integer(oauth2_time_now_sec()));
	payload = json_dumps(assertion, JSON_PRESERVE_ORDER | JSON_COMPACT);

	hdr = cjose_header_new(&err);
	if (hdr == NULL) {
		oauth2_error(log, "cjose_header_new failed: %s", err.message);
		goto end;
	}
	if (cjose_header_set(hdr, CJOSE_HDR_ALG, alg, &err) == false) {
		oauth2_error(log, "cjose_header_set %s:%s failed: %s",
			     CJOSE_HDR_ALG, alg, err.message);
		goto end;
	}
	if (cjose_header_set(hdr, OAUTH2_JOSE_HDR_TYP, OAUTH2_JOSE_HDR_TYP_JWT,
			     &err) == false) {
		oauth2_error(log, "cjose_header_set %s:%s failed: %s",
			     OAUTH2_JOSE_HDR_TYP, OAUTH2_JOSE_HDR_TYP_JWT,
			     err.message);
		goto end;
	}

	jws = cjose_jws_sign(jwk, hdr, (const uint8_t *)payload,
			     strlen(payload), &err);
	if (jws == NULL) {
		oauth2_error(log, "cjose_jws_sign failed: %s", err.message);
		goto end;
	}

	if (cjose_jws_export(jws, &jwt, &err) == false) {
		oauth2_error(log, "cjose_jws_export failed: %s", err.message);
		goto end;
	}

	oauth2_nv_list_set(log, params, OAUTH2_CLIENT_ASSERTION_TYPE,
			   OAUTH2_CLIENT_ASSERTION_TYPE_JWT_BEARER);
	oauth2_nv_list_set(log, params, OAUTH2_CLIENT_ASSERTION, jwt);

	rc = true;

end:

	oauth2_debug(log, "leave");

	if (jti)
		oauth2_mem_free(jti);
	if (assertion)
		json_decref(assertion);
	if (payload)
		free(payload);
	if (hdr)
		cjose_header_release(hdr);
	if (jws)
		cjose_jws_release(jws);

	return rc;
}

static bool
oauth2_auth_client_secret_jwt(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
			      const oauth2_cfg_endpoint_auth_t *auth,
			      oauth2_nv_list_t *params)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	if ((auth->client_secret_jwt.client_id == NULL) ||
	    (auth->client_secret_jwt.jwk == NULL) ||
	    (auth->client_secret_jwt.aud == NULL))
		goto end;

	rc = _oauth2_add_signed_jwt(log, auth->client_secret_jwt.jwk,
				    CJOSE_HDR_ALG_HS256,
				    auth->client_secret_jwt.client_id,
				    auth->client_secret_jwt.aud, params);

end:

	oauth2_debug(log, "leave");

	return rc;
}

static bool oauth2_auth_private_key_jwt(oauth2_log_t *log,
					oauth2_http_call_ctx_t *ctx,
					const oauth2_cfg_endpoint_auth_t *auth,
					oauth2_nv_list_t *params)
{
	bool rc = false;
	cjose_err err;
	// cjose_jwk_t *jwk = NULL;

	oauth2_debug(log, "enter");

	if ((auth->private_key_jwt.client_id == NULL) ||
	    (auth->private_key_jwt.jwk == NULL) ||
	    (auth->private_key_jwt.aud == NULL))
		goto end;

	//	jwk = cjose_jwk_import(cser_jwk, strlen(cser_jwk), &err);
	//	if (jwk == NULL) {
	//		oauth2_error(log, "cjose_jwk_import failed: %s",
	// err.message); 		goto end;
	//	}

	if (cjose_jwk_get_kty(auth->private_key_jwt.jwk, &err) !=
	    CJOSE_JWK_KTY_RSA) {
		oauth2_error(log, "jwk is not an RSA key: %s", err.message);
		goto end;
	}

	rc = _oauth2_add_signed_jwt(
	    log, auth->private_key_jwt.jwk, CJOSE_HDR_ALG_RS256,
	    auth->private_key_jwt.client_id, auth->private_key_jwt.aud, params);

end:

	oauth2_debug(log, "leave");

	return rc;
}

static bool
oauth2_auth_client_secret_basic(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
				const oauth2_cfg_endpoint_auth_t *auth,
				oauth2_nv_list_t *params)
{
	bool rc = false;

	if ((auth->client_secret_basic.client_id == NULL) ||
	    (auth->client_secret_basic.client_secret == NULL))
		goto end;

	rc = oauth2_http_call_ctx_basic_auth_set(
	    log, ctx, auth->client_secret_basic.client_id,
	    auth->client_secret_basic.client_secret, true);
end:

	return rc;
}

static bool
oauth2_auth_client_secret_post(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
			       const oauth2_cfg_endpoint_auth_t *auth,
			       oauth2_nv_list_t *params)
{
	bool rc = false;

	if ((auth->client_secret_post.client_id == NULL) ||
	    (auth->client_secret_post.client_secret == NULL))
		goto end;

	rc = oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID,
				auth->client_secret_post.client_id);

	if (rc == false)
		goto end;

	rc = oauth2_nv_list_add(log, params, OAUTH2_CLIENT_SECRET,
				auth->client_secret_post.client_secret);

end:

	return rc;
}

static bool oauth2_auth_client_cert(oauth2_log_t *log,
				    oauth2_http_call_ctx_t *ctx,
				    const oauth2_cfg_endpoint_auth_t *auth,
				    oauth2_nv_list_t *params)
{
	bool rc = false;

	if ((auth->client_cert.certfile == NULL) ||
	    (auth->client_cert.keyfile == NULL))
		goto end;

	rc = oauth2_http_auth_client_cert(log, auth->client_cert.certfile,
					  auth->client_cert.keyfile, ctx);

end:

	return rc;
}

bool oauth2_auth_basic(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
		       const oauth2_cfg_endpoint_auth_t *auth,
		       oauth2_nv_list_t *params)
{
	bool rc = false;

	rc = oauth2_http_auth_basic(log, auth->basic.username,
				    auth->basic.password, ctx);

	return rc;
}

typedef bool(oauth2_http_ctx_add_auth_cb_t)(
    oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
    const oauth2_cfg_endpoint_auth_t *auth, oauth2_nv_list_t *params);

typedef struct oauth2_http_ctx_auth_cb_ctx_t {
	oauth2_cfg_endpoint_auth_type_t type;
	oauth2_http_ctx_add_auth_cb_t *add_callback;
} oauth2_http_ctx_auth_cb_ctx_t;

// clang-format off
static oauth2_http_ctx_auth_cb_ctx_t oauth2_http_ctx_auth_cb[] = {
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC,	oauth2_auth_client_secret_basic	},
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST,	oauth2_auth_client_secret_post	},
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT,	oauth2_auth_client_secret_jwt	},
	{ OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT,		oauth2_auth_private_key_jwt		},
	{ OAUTH2_ENDPOINT_AUTH_CLIENT_CERT,			oauth2_auth_client_cert			},
	{ OAUTH2_ENDPOINT_AUTH_BASIC,				oauth2_auth_basic				},
	// must be last
	{ OAUTH2_ENDPOINT_AUTH_NONE,				NULL 							},
};
// clang-format on

bool oauth2_http_ctx_auth_add(oauth2_log_t *log, oauth2_http_call_ctx_t *ctx,
			      const oauth2_cfg_endpoint_auth_t *auth,
			      oauth2_nv_list_t *params)
{
	bool rc = false;
	int i = 0;

	if ((ctx == NULL) || (auth == NULL))
		goto end;

	if (auth->type == OAUTH2_ENDPOINT_AUTH_NONE) {
		rc = true;
		goto end;
	}

	i = 0;
	while (oauth2_http_ctx_auth_cb[i].type != OAUTH2_ENDPOINT_AUTH_NONE) {
		if (auth->type == oauth2_http_ctx_auth_cb[i].type) {
			rc = oauth2_http_ctx_auth_cb[i].add_callback(
			    log, ctx, auth, params);
			goto end;
		}
		i++;
	}

end:

	return rc;
}

/*
 * introspect
 */

_OAUTH2_CFG_CTX_TYPE_START(oauth2_introspect_ctx)
oauth2_cfg_endpoint_t *endpoint;
_OAUTH2_CFG_CTX_TYPE_END(oauth2_introspect_ctx)

_OAUTH2_CFG_CTX_INIT_START(oauth2_introspect_ctx)
ctx->endpoint = NULL;
_OAUTH2_CFG_CTX_INIT_END

_OAUTH2_CFG_CTX_CLONE_START(oauth2_introspect_ctx)
dst->endpoint = oauth2_cfg_endpoint_clone(log, src->endpoint);
_OAUTH2_CFG_CTX_CLONE_END

_OAUTH2_CFG_CTX_FREE_START(oauth2_introspect_ctx)
if (ctx->endpoint)
	oauth2_cfg_endpoint_free(log, ctx->endpoint);
_OAUTH2_CFG_CTX_FREE_END

_OAUTH2_CFG_CTX_FUNCS(oauth2_introspect_ctx)

#define OAUTH2_INTROSPECT_TOKEN "token"

#define OAUTH2_INTROSPECT_TOKEN_TYPE_HINT "token_type_hint"
#define OAUTH2_INTROSPECT_TOKEN_TYPE_HINT_ACCESS_TOKEN "access_token"

#define OAUTH2_INTROSPECT_CLAIM_ACTIVE "active"

static bool _oauth2_introspect_verify(oauth2_log_t *log,
				      oauth2_introspect_ctx_t *ctx,
				      const char *token, json_t **json_payload,
				      char **s_payload)
{
	bool rc = false;
	oauth2_nv_list_t *params = NULL;
	oauth2_http_call_ctx_t *http_ctx = NULL;
	json_t *active = NULL;
	oauth2_uint_t status_code = 0;

	oauth2_debug(log, "enter");

	http_ctx = oauth2_http_call_ctx_init(log);
	if (http_ctx == NULL)
		goto end;

	if (oauth2_http_call_ctx_ssl_verify_set(
		log, http_ctx,
		oauth2_cfg_endpoint_get_ssl_verify(ctx->endpoint)) == false)
		goto end;

	params = oauth2_nv_list_init(log);
	if (params == NULL)
		goto end;

	oauth2_nv_list_add(log, params, OAUTH2_INTROSPECT_TOKEN, token);
	oauth2_nv_list_add(log, params, OAUTH2_INTROSPECT_TOKEN_TYPE_HINT,
			   OAUTH2_INTROSPECT_TOKEN_TYPE_HINT_ACCESS_TOKEN);

	// TODO: add configurable extra POST params

	if (oauth2_http_ctx_auth_add(
		log, http_ctx, oauth2_cfg_endpoint_get_auth(ctx->endpoint),
		params) == false)
		goto end;

	if (oauth2_http_post_form(
		log, oauth2_cfg_endpoint_get_url(ctx->endpoint), params,
		http_ctx, s_payload, &status_code) == false)
		goto end;

	if ((status_code < 200) || (status_code >= 300)) {
		rc = false;
		goto end;
	}

	if (oauth2_json_decode_check_error(log, *s_payload, json_payload) ==
	    false)
		goto end;

	active = json_object_get(*json_payload, OAUTH2_INTROSPECT_CLAIM_ACTIVE);
	if (active == NULL)
		goto end;

	if (json_is_boolean(active) == false)
		goto end;

	if (json_is_true(active) == false) {
		oauth2_error(
		    log,
		    "\"%s\" boolean object with value \"false\" found in "
		    "response JSON object",
		    OAUTH2_INTROSPECT_CLAIM_ACTIVE);
		goto end;
	}

	rc = true;

	// TODO: verify if returned content is JWT? how to call into existing
	// jwks_uri etc. code?

end:

	if (rc == false) {
		if ((json_payload) && (*json_payload)) {
			json_decref(*json_payload);
			*json_payload = NULL;
		}
		if ((s_payload) && (*s_payload)) {
			oauth2_mem_free(*s_payload);
			*s_payload = NULL;
		}
	}

	if (params)
		oauth2_nv_list_free(log, params);
	if (http_ctx)
		oauth2_http_call_ctx_free(log, http_ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _oauth2_introspect_verify_callback(
    oauth2_log_t *log, oauth2_cfg_token_verify_t *verify, const char *token,
    json_t **json_payload, char **s_payload)
{
	bool rc = false;
	oauth2_introspect_ctx_t *ctx = NULL;

	ctx = (oauth2_introspect_ctx_t *)verify->ctx->ptr;

	if ((verify == NULL) || (verify->ctx == NULL) ||
	    (verify->ctx->ptr == NULL))
		goto end;

	rc =
	    _oauth2_introspect_verify(log, ctx, token, json_payload, s_payload);

end:

	return rc;
}

static char *_oauth2_verify_options_set_introspect_url_ctx(
    oauth2_log_t *log, const char *url, const oauth2_nv_list_t *params,
    oauth2_introspect_ctx_t *ctx)
{
	char *rv = NULL;

	oauth2_debug(log, "enter");

	ctx->endpoint = oauth2_cfg_endpoint_init(log);
	rv = oauth2_cfg_set_endpoint(log, ctx->endpoint, url, params,
				     "introspect");

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_verify_options_set_introspect_url)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;
	char *rv = NULL;

	oauth2_debug(log, "enter");

	verify->callback = _oauth2_introspect_verify_callback;
	verify->ctx->callbacks = &oauth2_introspect_ctx_funcs;
	verify->ctx->ptr = verify->ctx->callbacks->init(log);

	rv = _oauth2_verify_options_set_introspect_url_ctx(
	    log, value, params, (oauth2_introspect_ctx_t *)verify->ctx->ptr);

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

_OAUTH2_CFG_CTX_TYPE_START(oauth2_metadata_ctx)
oauth2_introspect_ctx_t *introspect;
oauth2_jose_jwt_verify_ctx_t *jwks_uri_verify;
oauth2_uri_ctx_t *metadata_uri;
_OAUTH2_CFG_CTX_TYPE_END(oauth2_metadata_ctx)

_OAUTH2_CFG_CTX_INIT_START(oauth2_metadata_ctx)
ctx->introspect = oauth2_introspect_ctx_init(log);
ctx->jwks_uri_verify =
    (oauth2_jose_jwt_verify_ctx_t *)oauth2_jose_jwt_verify_ctx_init(log);
ctx->metadata_uri = oauth2_uri_ctx_init(log);
_OAUTH2_CFG_CTX_INIT_END

_OAUTH2_CFG_CTX_CLONE_START(oauth2_metadata_ctx)
dst->introspect = oauth2_introspect_ctx_clone(log, src->introspect);
dst->jwks_uri_verify =
    oauth2_jose_jwt_verify_ctx_clone(log, src->jwks_uri_verify);
dst->metadata_uri = oauth2_uri_ctx_clone(log, src->metadata_uri);
_OAUTH2_CFG_CTX_CLONE_END

_OAUTH2_CFG_CTX_FREE_START(oauth2_metadata_ctx)
if (ctx->introspect)
	oauth2_introspect_ctx_free(log, ctx->introspect);
if (ctx->jwks_uri_verify)
	oauth2_jose_jwt_verify_ctx_free(log, ctx->jwks_uri_verify);
if (ctx->metadata_uri)
	oauth2_uri_ctx_free(log, ctx->metadata_uri);
_OAUTH2_CFG_CTX_FREE_END

_OAUTH2_CFG_CTX_FUNCS(oauth2_metadata_ctx)

static bool _oauth2_metadata_verify_callback(oauth2_log_t *log,
					     oauth2_cfg_token_verify_t *verify,
					     const char *token,
					     json_t **json_payload,
					     char **s_payload)
{
	bool rc = false;
	oauth2_metadata_ctx_t *ptr = NULL;
	bool refresh = false;
	char *response = NULL;
	json_t *json_metadata = NULL, *json_jwks_uri = NULL,
	       *json_introspection_endpoint;
	const char *jwks_uri = NULL, *introspection_endpoint = NULL;
	char *peek = NULL;

	if ((verify == NULL) || (verify->ctx == NULL) ||
	    (verify->ctx->ptr == NULL))
		goto end;

	ptr = (oauth2_metadata_ctx_t *)verify->ctx->ptr;

	response =
	    oauth2_jose_resolve_from_uri(log, ptr->metadata_uri, &refresh);
	if (response == NULL)
		goto end;

	if (oauth2_json_decode_object(log, response, &json_metadata) == false)
		goto end;

	peek = oauth2_jose_jwt_header_peek(log, token, NULL);
	if (peek) {
		oauth2_debug(log, "JWT token: header=%s", peek);
		goto jwks_uri;
	} else {
		oauth2_debug(log, "no JWT token: introspect it");
		goto introspect;
	}

jwks_uri:

	json_jwks_uri = json_object_get(json_metadata, "jwks_uri");
	if (json_jwks_uri) {
		if (json_is_string(json_jwks_uri)) {
			jwks_uri = json_string_value(json_jwks_uri);
		} else {
			oauth2_warn(log, "\"jwks_uri\" value is not a string");
		}
	}

	if (jwks_uri) {
		oauth2_cfg_endpoint_set_url(
		    ptr->jwks_uri_verify->jwks_provider->jwks_uri->endpoint,
		    jwks_uri);
		rc = oauth2_jose_jwt_verify(log, ptr->jwks_uri_verify, token,
					    json_payload, s_payload);
		if (rc == true)
			goto end;
	}

introspect:

	json_introspection_endpoint =
	    json_object_get(json_metadata, "introspection_endpoint");
	if (json_introspection_endpoint) {
		if (json_is_string(json_introspection_endpoint)) {
			introspection_endpoint =
			    json_string_value(json_introspection_endpoint);
		} else {
			oauth2_warn(
			    log,
			    "\"introspection_endpoint\" value is not a string");
		}
	}

	if (introspection_endpoint) {
		oauth2_cfg_endpoint_set_url(ptr->introspect->endpoint,
					    introspection_endpoint);
		rc = _oauth2_introspect_verify(log, ptr->introspect, token,
					       json_payload, s_payload);
		if (rc == true)
			goto end;
	}

end:

	if (peek)
		oauth2_mem_free(peek);
	if (json_metadata)
		json_decref(json_metadata);
	if (response)
		oauth2_mem_free(response);

	return rc;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_verify_options_set_metadata_url)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;
	char *rv = NULL;
	oauth2_metadata_ctx_t *ptr = NULL;

	oauth2_debug(log, "enter");

	verify->callback = _oauth2_metadata_verify_callback;
	verify->ctx->callbacks = &oauth2_metadata_ctx_funcs;
	verify->ctx->ptr = verify->ctx->callbacks->init(log);
	ptr = (oauth2_metadata_ctx_t *)verify->ctx->ptr;

	rv = _oauth2_verify_options_set_introspect_url_ctx(log, value, params,
							   ptr->introspect);
	if (rv != NULL)
		goto end;

	// TODO: should we not combine these next 2 calls in a single function?
	if (oauth2_jose_jwt_verify_set_options(
		log, ptr->jwks_uri_verify, OAUTH2_JOSE_JWKS_PROVIDER_JWKS_URI,
		params) == false) {
		rv = oauth2_strdup("oauth2_jose_jwt_verify_set_options failed");
		goto end;
	}

	rv = oauth2_jose_options_uri_ctx(
	    log, value, params, ptr->jwks_uri_verify->jwks_provider->jwks_uri,
	    "jwks_uri");
	if (rv != NULL) {
		rv = oauth2_strdup(
		    "oauth2_jose_options_uri_ctx failed for jwks_uri");
		goto end;
	}

	rv = oauth2_jose_options_uri_ctx(log, value, params, ptr->metadata_uri,
					 "metadata");
	if (rv != NULL) {
		rv = oauth2_strdup(
		    "oauth2_jose_options_uri_ctx failed for metadata");
		goto end;
	}

end:

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

#define OAUTH_DPOP_HDR_JWK "jwk"
#define OAUTH_DPOP_CLAIM_HTM "htm"
#define OAUTH_DPOP_CLAIM_HTU "htu"
#define OAUTH_DPOP_HDR_TYP_VALUE "dpop+jwt"

static bool _oauth2_dpop_parse_and_verify(oauth2_log_t *log,
					  oauth2_cfg_dpop_verify_t *verify,
					  oauth2_http_request_t *request,
					  cjose_jwk_t **jwk)
{
	bool rc = false;
	char *s_value = NULL;
	const char *s_dpop = NULL;
	cjose_jws_t *jws = NULL;
	cjose_header_t *hdr = NULL;
	uint8_t *plaintext = NULL;
	size_t plaintext_len = 0;
	char *s_payload = NULL, *s_peek = NULL;
	json_t *dpop_payload = NULL;
	char *url = NULL;
	const char *method = NULL;
	cjose_err err;
	const char *hdr_typ = NULL, *hdr_alg = NULL;
	char *hdr_jwk = NULL;
	char *clm_htm = NULL, *clm_htu = NULL, *clm_jti = NULL;
	json_int_t clm_iat;

	if ((request == NULL) || (verify == NULL) || (jwk == NULL))
		goto end;

	s_dpop =
	    oauth2_http_request_header_get(log, request, OAUTH2_HTTP_HDR_DPOP);
	if (s_dpop == NULL)
		goto end;

	s_peek = oauth2_jose_jwt_header_peek(log, s_dpop, NULL);
	if (s_peek)
		oauth2_debug(log, "DPOP header: %s", s_peek);

	/*
	 * 1.  the string value is a well-formed JWT,
	 */

	jws = cjose_jws_import(s_dpop, strlen(s_dpop), &err);
	if (jws == NULL) {
		oauth2_error(log, "cjose_jws_import failed: %s", err.message);
		goto end;
	}

	hdr = cjose_jws_get_protected(jws);
	if (hdr == NULL)
		goto end;

	if (cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err) ==
	    false) {
		oauth2_error(log, "cjose_jws_get_plaintext failed: %s",
			     err.message);
		goto end;
	}

	s_payload = oauth2_strndup((const char *)plaintext, plaintext_len);

	oauth2_debug(log, "DPOP payload: %s", s_payload);

	if (oauth2_json_decode_object(log, s_payload, &dpop_payload) == false) {
		oauth2_error(log, "decoding JWT payload failed");
		goto end;
	}

	/*
	 * 2.  all required claims are contained in the JWT,
	 */

	hdr_typ = cjose_header_get(hdr, OAUTH2_JOSE_HDR_TYP, &err);
	if (hdr_typ == NULL) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP header",
			     OAUTH2_JOSE_HDR_TYP);
		goto end;
	}

	hdr_alg = cjose_header_get(hdr, CJOSE_HDR_ALG, &err);
	if (hdr_alg == NULL) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP header",
			     CJOSE_HDR_ALG);
		goto end;
	}

	hdr_jwk = cjose_header_get_raw(hdr, OAUTH_DPOP_HDR_JWK, &err);
	if (hdr_jwk == NULL) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP header",
			     OAUTH_DPOP_HDR_JWK);
		goto end;
	}

	*jwk = cjose_jwk_import(hdr_jwk, strlen(hdr_jwk), &err);
	if (*jwk == NULL) {
		oauth2_error(log, "cjose_jwk_import failed: %s", err.message);
		goto end;
	}

	if (oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_HTU,
				   &clm_htu, NULL) == false) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH_DPOP_CLAIM_HTU);
		goto end;
	}

	if (oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_HTM,
				   &clm_htm, NULL) == false) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH_DPOP_CLAIM_HTM);
		goto end;
	}

	if (oauth2_json_string_get(log, dpop_payload, OAUTH2_CLAIM_JTI,
				   &clm_jti, NULL) == false) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH2_CLAIM_JTI);
		goto end;
	}

	if (oauth2_json_number_get(log, dpop_payload, OAUTH2_CLAIM_IAT,
				   &clm_iat, 0) == false) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH2_CLAIM_IAT);
		goto end;
	}

	/*
	 * 3.  the "typ" field in the header has the value "dpop+jwt",
	 */

	if (strcasecmp(hdr_typ, OAUTH_DPOP_HDR_TYP_VALUE) != 0) {
		oauth2_error(
		    log,
		    "the %s header value (%s) does not match DPOP value (%s)",
		    OAUTH2_JOSE_HDR_TYP, hdr_typ, OAUTH_DPOP_HDR_TYP_VALUE);
		goto end;
	}

	/*
	 * 4.  the algorithm in the header of the JWT indicates an asymmetric
	 *    digital signature algorithm, is not "none", is supported by the
	 *   application, and is deemed secure,
	 */

	if (strcasecmp(hdr_alg, CJOSE_HDR_ALG_NONE) == 0) {
		oauth2_error(log, "the %s header value cannot be \"%s\"",
			     CJOSE_HDR_ALG, CJOSE_HDR_ALG_NONE);
		goto end;
	}

	if ((strstr(hdr_alg, "RS") != hdr_alg) &&
	    (strstr(hdr_alg, "PS") != hdr_alg) &&
	    (strstr(hdr_alg, "ES") != hdr_alg)) {
		oauth2_error(log,
			     "the %s header value must be asymmetric and "
			     "starting with \"RS\", \"PS\" or \"ES\".",
			     CJOSE_HDR_ALG);
		goto end;
	}

	/*
	 * 5.  that the JWT is signed using the public key contained in the
	 *   "jwk" header of the JWT,
	 */
	if (cjose_jws_verify(jws, *jwk, &err) == false) {
		oauth2_error(log, "DPOP signature verification failed: %s",
			     err.message);
		goto end;
	}

	/*
	 * 6.  the "htm" claim matches the HTTP method value of the HTTP request
	 *  in which the JWT was received (case-insensitive),
	 */

	method = oauth2_http_request_method_get_str(log, request);
	if (strcasecmp(method, clm_htm) != 0) {
		oauth2_error(log,
			     "requested HTTP method (%s) does not match DPOP "
			     "\"%s\" value (%s)",
			     method, OAUTH_DPOP_CLAIM_HTM, clm_htm);
	}

	/*
	 * 7.  the "htu" claims matches the HTTP URI value for the HTTP request
	 *    in which the JWT was received, ignoring any query and fragment
	 *    parts,
	 */

	url = oauth2_http_request_url_path_get(log, request);
	if (url == NULL)
		goto end;

	if (strcasecmp(url, clm_htu) != 0) {
		oauth2_error(
		    log,
		    "requested URL (%s) does not match DPOP \"%s\" value (%s)",
		    url, OAUTH_DPOP_CLAIM_HTU, clm_htu);
		goto end;
	}

	/*
	 * 8.  the token was issued within an acceptable timeframe (see
	 *     Section 9.1), and
	 */
	if (oauth2_jose_jwt_validate_iat(
		log, dpop_payload, verify->iat_validate,
		verify->iat_slack_before, verify->iat_slack_after) == false)
		goto end;

	/*
	 * 9.  that, within a reasonable consideration of accuracy and resource
	 *     utilization, a JWT with the same "jti" value has not been
	 *     received previously (see Section 9.1).
	 */

	oauth2_cache_get(log, verify->cache, clm_jti, &s_value);
	if (s_value != NULL) {
		oauth2_error(log, "a token with the same JTI \"%s\" exists in "
				  "the cache: possible replay attack");
		goto end;
	}

	oauth2_cache_set(log, verify->cache, clm_jti, s_dpop, verify->expiry_s);

	rc = true;

end:

	if (s_peek)
		oauth2_mem_free(s_peek);
	if (s_value)
		oauth2_mem_free(s_value);
	if (clm_htu)
		oauth2_mem_free(clm_htu);
	if (clm_htm)
		oauth2_mem_free(clm_htm);
	if (clm_jti)
		oauth2_mem_free(clm_jti);
	if (hdr_jwk)
		cjose_get_dealloc()(hdr_jwk);
	if (url)
		oauth2_mem_free(url);
	if (s_payload)
		oauth2_mem_free(s_payload);
	if (dpop_payload)
		json_decref(dpop_payload);
	if (jws)
		cjose_jws_release(jws);

	return rc;
}

#define OAUTH_DPOP_CLAIM_CNF "cnf"
#define OAUTH_DPOP_CLAIM_CNF_JKT "jkt"

static bool _oauth2_token_verify_dpop(oauth2_log_t *log,
				      oauth2_cfg_dpop_verify_t *verify,
				      oauth2_http_request_t *request,
				      json_t *json_payload)
{
	bool rc = false;
	cjose_jwk_t *jwk = NULL;
	json_t *cnf = NULL;
	char *calc_thumb = NULL;
	const char *prov_thumb = NULL;
	unsigned char *hash_bytes = NULL;
	unsigned int hash_bytes_len = 0;
	uint8_t *dst = NULL;
	size_t dst_len = 0;

	if ((request == NULL) || (json_payload == NULL))
		goto end;

	if (_oauth2_dpop_parse_and_verify(log, verify, request, &jwk) == false)
		goto end;

	if (oauth2_jose_jwk_thumbprint(log, jwk, &hash_bytes,
				       &hash_bytes_len) == false) {
		oauth2_error(log, "oauth2_jose_jwk_thumbprint failed");
		goto end;
	}

	cnf = json_object_get(json_payload, OAUTH_DPOP_CLAIM_CNF);
	if (cnf == NULL) {
		oauth2_error(log, "no \"%s\" claim found",
			     OAUTH_DPOP_CLAIM_CNF);
		goto end;
	}

	prov_thumb =
	    json_string_value(json_object_get(cnf, OAUTH_DPOP_CLAIM_CNF_JKT));

	if (oauth2_base64url_decode(log, prov_thumb, &dst, &dst_len) == false) {
		oauth2_error(log, "oauth2_base64url_decode failed");
		goto end;
	}

	if ((hash_bytes_len != dst_len) ||
	    (memcmp(hash_bytes, dst, hash_bytes_len)) != 0) {
		oauth2_error(log,
			     "public key thumbprint in DPOP \"%s\" does not "
			     "match \"%s\" claim \%s\" in JWT token",
			     calc_thumb, OAUTH_DPOP_CLAIM_CNF_JKT, prov_thumb);
		goto end;
	}

	rc = true;

end:

	if (dst)
		oauth2_mem_free(dst);
	if (hash_bytes)
		oauth2_mem_free(hash_bytes);
	if (calc_thumb)
		oauth2_mem_free(calc_thumb);
	if (jwk)
		cjose_jwk_release(jwk);

	return rc;
}

bool oauth2_token_verify(oauth2_log_t *log, oauth2_http_request_t *request,
			 oauth2_cfg_token_verify_t *verify, const char *token,
			 json_t **json_payload)
{

	bool rc = false;
	oauth2_cfg_token_verify_t *ptr = NULL;
	char *s_payload = NULL;

	oauth2_debug(log, "enter");

	if ((verify == NULL) || (token == NULL))
		goto end;

	ptr = verify;
	while (ptr && ptr->callback) {

		oauth2_cache_get(log, ptr->cache, token, &s_payload);
		if ((s_payload) &&
		    (oauth2_json_decode_object(log, s_payload, json_payload))) {
			rc = true;
			break;
		}

		if (ptr->callback(log, ptr, token, json_payload, &s_payload)) {
			oauth2_cache_set(log, ptr->cache, token, s_payload,
					 ptr->expiry_s);
			rc = true;
			break;
		}

		ptr = ptr->next;
	}

	if ((rc) && (ptr->type == OAUTH2_TOKEN_VERIFY_DPOP)) {
		rc = _oauth2_token_verify_dpop(log, &verify->dpop, request,
					       *json_payload);
	}

end:

	if (s_payload)
		oauth2_mem_free(s_payload);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

/*
void oauth2_scrub_headers(request_rec *r) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	if (cfg->scrub_request_headers != 0) {

		const char *prefix = oidc_cfg_claim_prefix(r);
		apr_hash_t *hdrs = apr_hash_make(r->pool);

		if (apr_strnatcmp(prefix, "") == 0) {
			if ((cfg->white_listed_claims != NULL)
					&&
(apr_hash_count(cfg->white_listed_claims) > 0)) hdrs = apr_hash_overlay(r->pool,
cfg->white_listed_claims, hdrs); else oidc_warn(r, "both " OIDCClaimPrefix " and
" OIDCWhiteListedClaims " are empty: this renders an insecure setup!");
		}

		char *authn_hdr = oidc_cfg_dir_authn_header(r);
		if (authn_hdr != NULL)
			apr_hash_set(hdrs, authn_hdr, APR_HASH_KEY_STRING,
authn_hdr);

		oidc_scrub_request_headers(r, OIDC_DEFAULT_HEADER_PREFIX, hdrs);

		if ((strstr(prefix, OIDC_DEFAULT_HEADER_PREFIX) != prefix)) {
			oidc_scrub_request_headers(r, prefix, NULL);
		}
	}
}
*/
