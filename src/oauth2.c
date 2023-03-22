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

#include "oauth2/oauth2.h"
#include "cfg_int.h"
#include "oauth2/cfg.h"
#include "oauth2/http.h"
#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include "jose_int.h"
#include "oauth2_int.h"
#include "util_int.h"

#include <cjose/cjose.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

/*
 * auth
 */

#define OAUTH2_CLIENT_ASSERTION "client_assertion"
#define OAUTH2_CLIENT_ASSERTION_TYPE "client_assertion_type"
#define OAUTH2_CLIENT_ASSERTION_TYPE_JWT_BEARER                                \
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

static bool _oauth2_add_signed_jwt(oauth2_log_t *log, cjose_jwk_t *jwk,
				   const char *alg, const char *client_id,
				   const char *aud, oauth2_nv_list_t *params)
{

	bool rc = false;
	char *jwt = NULL;

	oauth2_debug(log, "enter");

	jwt = oauth2_jwt_create(log, jwk, alg, client_id, client_id, client_id,
				aud, 60, true, true);
	if (jwt == NULL)
		goto end;

	oauth2_nv_list_set(log, params, OAUTH2_CLIENT_ASSERTION_TYPE,
			   OAUTH2_CLIENT_ASSERTION_TYPE_JWT_BEARER);
	oauth2_nv_list_set(log, params, OAUTH2_CLIENT_ASSERTION, jwt);

	rc = true;

end:

	if (jwt)
		oauth2_mem_free(jwt);

	oauth2_debug(log, "leave");

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
oauth2_nv_list_t *params;
_OAUTH2_CFG_CTX_TYPE_END(oauth2_introspect_ctx)

_OAUTH2_CFG_CTX_INIT_START(oauth2_introspect_ctx)
ctx->endpoint = NULL;
ctx->params = NULL;
_OAUTH2_CFG_CTX_INIT_END

_OAUTH2_CFG_CTX_CLONE_START(oauth2_introspect_ctx)
dst->endpoint = oauth2_cfg_endpoint_clone(log, src->endpoint);
dst->params = oauth2_nv_list_clone(log, src->params);
_OAUTH2_CFG_CTX_CLONE_END

_OAUTH2_CFG_CTX_FREE_START(oauth2_introspect_ctx)
if (ctx->endpoint)
	oauth2_cfg_endpoint_free(log, ctx->endpoint);
if (ctx->params)
	oauth2_nv_list_free(log, ctx->params);
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
	oauth2_http_call_ctx_outgoing_proxy_set(
	    log, http_ctx,
	    oauth2_cfg_endpoint_get_outgoing_proxy(ctx->endpoint));

	params = oauth2_nv_list_init(log);
	if (params == NULL)
		goto end;

	oauth2_nv_list_add(log, params, OAUTH2_INTROSPECT_TOKEN, token);
	oauth2_nv_list_add(log, params, OAUTH2_INTROSPECT_TOKEN_TYPE_HINT,
			   OAUTH2_INTROSPECT_TOKEN_TYPE_HINT_ACCESS_TOKEN);

	oauth2_nv_list_merge_into(log, ctx->params, params);

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
	if (active == NULL) {
		oauth2_error(log,
			     "no claim \"%s\" found in introspection response",
			     OAUTH2_INTROSPECT_CLAIM_ACTIVE);
		goto end;
	}

	if (json_is_boolean(active) == false) {
		oauth2_error(log,
			     "claim \"%s\" in introspection response "
			     "is not a boolean",
			     OAUTH2_INTROSPECT_CLAIM_ACTIVE);
		goto end;
	}

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

	if (oauth2_parse_form_encoded_params(
		log, oauth2_nv_list_get(log, params, "introspect.params"),
		&ctx->params) == false)
		rv = oauth2_strdup("oauth2_parse_form_encoded_params failed");

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
if (dst->introspect)
	oauth2_introspect_ctx_free(log, dst->introspect);
dst->introspect = oauth2_introspect_ctx_clone(log, src->introspect);
if (dst->jwks_uri_verify)
	oauth2_jose_jwt_verify_ctx_free(log, dst->jwks_uri_verify);
dst->jwks_uri_verify =
    oauth2_jose_jwt_verify_ctx_clone(log, src->jwks_uri_verify);
if (dst->metadata_uri)
	oauth2_uri_ctx_free(log, dst->metadata_uri);
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
	oauth2_jose_jwt_verify_ctx_t *jwks_uri_verify = NULL;
	oauth2_introspect_ctx_t *introspect_ctx = NULL;
	const char *jwks_uri = NULL, *introspection_uri = NULL;
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
		// NB: need a copy because we're going to modify a static/shared
		// config setting
		jwks_uri_verify =
		    oauth2_jose_jwt_verify_ctx_clone(log, ptr->jwks_uri_verify);
		oauth2_cfg_endpoint_set_url(
		    jwks_uri_verify->jwks_provider->jwks_uri->endpoint,
		    jwks_uri);
		rc = oauth2_jose_jwt_verify(log, jwks_uri_verify, token,
					    json_payload, s_payload);
		if (rc == true)
			goto end;
	}

introspect:

	json_introspection_endpoint =
	    json_object_get(json_metadata, "introspection_endpoint");
	if (json_introspection_endpoint) {
		if (json_is_string(json_introspection_endpoint)) {
			introspection_uri =
			    json_string_value(json_introspection_endpoint);
		} else {
			oauth2_warn(
			    log,
			    "\"introspection_endpoint\" value is not a string");
		}
	}

	if (introspection_uri) {
		// NB: need a copy because we're going to modify a static/shared
		// config setting
		introspect_ctx =
		    oauth2_introspect_ctx_clone(log, ptr->introspect);
		oauth2_cfg_endpoint_set_url(introspect_ctx->endpoint,
					    introspection_uri);
		rc = _oauth2_introspect_verify(log, introspect_ctx, token,
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
	if (jwks_uri_verify)
		oauth2_jose_jwt_verify_ctx_free(log, jwks_uri_verify);
	if (introspect_ctx)
		oauth2_introspect_ctx_free(log, introspect_ctx);

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

static const char *
oauth2_mtls_verify_policy2str(const oauth2_cfg_mtls_verify_policy_t policy)
{
	if (policy == OAUTH2_MTLS_VERIFY_POLICY_OPTIONAL)
		return "optional";
	if (policy == OAUTH2_MTLS_VERIFY_POLICY_REQUIRED)
		return "required";
	return "unset";
}

static char *
oauth2_mtls_client_cert_fingerprint(oauth2_log_t *log,
				    oauth2_cfg_mtls_verify_t *mtls_verify,
				    const oauth2_http_request_t *request)
{
	BIO *input = NULL;
	X509 *x509 = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	char *fingerprint = NULL;
	const char *cert_pem = NULL;

	if (mtls_verify == NULL)
		goto end;

	cert_pem = oauth2_http_request_context_get(log, request,
						   OAUTH2_TLS_CERT_VAR_NAME);

	oauth2_debug(log, "request context variable: %s=%s",
		     OAUTH2_TLS_CERT_VAR_NAME, cert_pem);
	if (cert_pem == NULL)
		goto end;

	input = BIO_new(BIO_s_mem());
	if (input == NULL) {
		oauth2_error(log, "memory allocation BIO_new/BIO_s_mem");
		goto end;
	}

	if (BIO_puts(input, cert_pem) <= 0) {
		oauth2_error(log, "memory allocation BIO_new/BIO_s_mem");
		goto end;
	}

	x509 = PEM_read_bio_X509_AUX(input, NULL, NULL, NULL);
	if (x509 == NULL) {
		oauth2_error(log, "could not decode x509 cert from presumably "
				  "PEM encoded env var value");
		goto end;
	}

	if (!X509_digest(x509, EVP_sha256(), md, &md_len)) {
		oauth2_error(log, "X509_digest failed");
		goto end;
	}

	oauth2_base64url_encode(log, md, md_len, &fingerprint);

end:

	if (input)
		BIO_free(input);
	if (x509)
		X509_free(x509);

	return fingerprint;
}

oauth2_cfg_mtls_verify_policy_t
oauth2_mtls_verify_policy_get(const oauth2_cfg_mtls_verify_t *mtls_verify)
{
	if ((mtls_verify == NULL) ||
	    (mtls_verify->policy == OAUTH2_CFG_UINT_UNSET))
		return OAUTH2_MTLS_VERIFY_POLICY_REQUIRED;
	return mtls_verify->policy;
}

static bool oauth2_mtls_validate_cnf_x5t_s256(
    oauth2_log_t *log, oauth2_cfg_mtls_verify_t *mtls_verify,
    const oauth2_http_request_t *request, const char *x5t_256_str)
{
	bool rc = false;
	char *fingerprint = NULL;

	fingerprint =
	    oauth2_mtls_client_cert_fingerprint(log, mtls_verify, request);
	if (fingerprint == NULL) {
		oauth2_debug(log, "no certificate (fingerprint) provided");
		goto end;
	}

	if (strcmp(fingerprint, x5t_256_str) != 0) {
		oauth2_warn(log,
			    "fingerprint of provided cert (%s) does not match "
			    "cnf[\"x5t#S256\"] (%s)",
			    fingerprint, x5t_256_str);
		goto end;
	}

	oauth2_debug(
	    log, "fingerprint of provided cert (%s) matches cnf[\"x5t#S256\"]",
	    fingerprint);

	rc = true;

end:

	if (fingerprint)
		oauth2_mem_free(fingerprint);

	return rc;
}

#define OAUTH2_CLAIM_CNF "cnf"
#define OAUTH2_CLAIM_CNF_X5T_S256 "x5t#S256"

static bool oauth2_mtls_token_verify(oauth2_log_t *log,
				     oauth2_cfg_mtls_verify_t *mtls_verify,
				     const oauth2_http_request_t *request,
				     json_t *jwt)
{
	bool rc = false;
	char *cnf_x5t_s256_str = NULL;

	oauth2_debug(log, "enter: policy=%s",
		     oauth2_mtls_verify_policy2str(mtls_verify->policy));

	json_t *cnf = json_object_get(jwt, OAUTH2_CLAIM_CNF);
	// cnf = json_object();
	// json_object_set(cnf, "x5t#S256",
	// json_string("3rM_CLStQF3e-N2_9dZcR-BMw45XmRR0jbj6MSHU2bM"));
	if (cnf == NULL) {
		oauth2_debug(log, "no \"%s\" claim found in the token",
			     OAUTH2_CLAIM_CNF);
		goto err;
	}

	oauth2_json_string_get(log, cnf, OAUTH2_CLAIM_CNF_X5T_S256,
			       &cnf_x5t_s256_str, NULL);
	if (cnf_x5t_s256_str == NULL) {
		oauth2_debug(log,
			     " \"%s\" claim found in the token but no \"%s\" "
			     "key found inside",
			     OAUTH2_CLAIM_CNF, OAUTH2_CLAIM_CNF_X5T_S256);
		goto err;
	}

	rc = oauth2_mtls_validate_cnf_x5t_s256(log, mtls_verify, request,
					       cnf_x5t_s256_str);

	goto end;

err:

	if ((cnf_x5t_s256_str == NULL) &&
	    (oauth2_mtls_verify_policy_get(mtls_verify) !=
	     OAUTH2_MTLS_VERIFY_POLICY_REQUIRED))
		rc = true;

end:

	if (cnf_x5t_s256_str != NULL)
		oauth2_mem_free(cnf_x5t_s256_str);

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

	if (rc == true) {
		if (ptr->type == OAUTH2_TOKEN_VERIFY_DPOP) {
			rc = oauth2_dpop_token_verify(log, &verify->dpop,
						      request, *json_payload);
		} else if (ptr->type == OAUTH2_TOKEN_VERIFY_MTLS) {
			rc = oauth2_mtls_token_verify(log, &verify->mtls,
						      request, *json_payload);
		}
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
