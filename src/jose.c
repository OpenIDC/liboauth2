/***************************************************************************
 *
 * Copyright (C) 2018-2022 - ZmartZone Holding BV - www.zmartzone.eu
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

#include "oauth2/jose.h"
#include "oauth2/http.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include "cjose/cjose.h"

#include "cache_int.h"
#include "jose_int.h"
#include "util_int.h"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#endif

#define _OAUTH2_JOSE_OPENSSL_ERR_LOG(log, function)                            \
	oauth2_error(log, "%s failed: %s", function,                           \
		     ERR_error_string(ERR_get_error(), NULL))

#define _OAUTH2_JOSE_JANSSON_ERR_LOG(log, msg, json_err)                       \
	oauth2_error(log, "%s failed: %s", msg, json_err.text)

#if (OPENSSL_VERSION_NUMBER < 0x10100000) || defined(LIBRESSL_VERSION_NUMBER)
EVP_MD_CTX *EVP_MD_CTX_new()
{
	return oauth2_mem_alloc(sizeof(EVP_MD_CTX));
}
void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	if (ctx)
		oauth2_mem_free(ctx);
}
#endif

static oauth2_jose_jwk_t *oauth2_jose_jwk_new()
{
	oauth2_jose_jwk_t *jwk = oauth2_mem_alloc(sizeof(oauth2_jose_jwk_t));
	jwk->jwk = NULL;
	jwk->kid = NULL;
	return jwk;
}

static oauth2_jose_jwk_t *oauth2_jose_jwk_oct_new(oauth2_log_t *log,
						  unsigned char *key,
						  unsigned int key_len)
{
	oauth2_jose_jwk_t *rv = NULL;
	cjose_err err;
	cjose_jwk_t *c_jwk = NULL;

	c_jwk = cjose_jwk_create_oct_spec(key, key_len, &err);
	if (c_jwk == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jwk_create_oct_spec",
					  err);
		goto end;
	}

	oauth2_trace1(log, "jwk oct spec created", key_len);

	rv = oauth2_jose_jwk_new();
	if (rv == NULL)
		goto end;

	rv->jwk = c_jwk;

end:

	return rv;
}

void oauth2_jose_jwk_release(oauth2_jose_jwk_t *jwk)
{
	if (jwk->jwk) {
		cjose_jwk_release(jwk->jwk);
		jwk->jwk = NULL;
	}
	if (jwk->kid) {
		oauth2_mem_free(jwk->kid);
		jwk->kid = NULL;
	}
	oauth2_mem_free(jwk);
}

bool oauth2_jose_hash_bytes(oauth2_log_t *log, const char *digest,
			    const unsigned char *src, unsigned int src_len,
			    unsigned char **dst, unsigned int *dst_len)
{

	const EVP_MD *evp_digest = NULL;
	EVP_MD_CTX *ctx = NULL;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	bool rc = false;

	oauth2_debug(log, "enter");

	if ((dst == NULL) || (dst_len == NULL))
		goto end;

	if ((src == NULL) || (src_len == 0)) {
		oauth2_warn(log, "cannot hash empty string");
		goto end;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "EVP_MD_CTX_new");
		goto end;
	}

	EVP_MD_CTX_init(ctx);

	if ((evp_digest = EVP_get_digestbyname(digest)) == NULL) {
		oauth2_error(
		    log,
		    "no OpenSSL digest algorithm found for algorithm \"%s\"",
		    digest);
		goto end;
	}

	if (!EVP_DigestInit_ex(ctx, evp_digest, NULL))
		goto end;

	if (!EVP_DigestUpdate(ctx, src, src_len))
		goto end;

	if (!EVP_DigestFinal(ctx, md_value, dst_len))
		goto end;

	*dst = oauth2_mem_alloc((size_t)*dst_len);
	if (*dst == NULL) {
		*dst_len = 0;
		goto end;
	}

	memcpy(*dst, md_value, *dst_len);

	rc = true;

end:

	if (ctx)
		EVP_MD_CTX_free(ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_jose_jwk_create_symmetric(oauth2_log_t *log, const char *secret,
				      const char *hash_algo,
				      oauth2_jose_jwk_t **jwk)
{
	unsigned char *key = NULL;
	unsigned int key_len = 0;
	bool rv = false, rc = false;

	oauth2_debug(log, "enter");

	if (jwk == NULL)
		goto end;

	oauth2_trace1(log, "secret: %s", secret);

	if (hash_algo != NULL) {
		/*
		 * hash the client_secret first, this is OpenID Connect specific
		 */
		rc = oauth2_jose_hash_bytes(
		    log, hash_algo, (const unsigned char *)secret,
		    secret ? strlen(secret) : 0, &key, &key_len);
		if (rc == false) {
			oauth2_error(log, "oauth2_jose_hash_bytes failed");
			goto end;
		}
	} else if (secret != NULL) {
		key_len = strlen(secret);
		key = (unsigned char *)oauth2_strdup(secret);
	}
	oauth2_trace1(log, "key and key_len (%d) set", key_len);

	*jwk = oauth2_jose_jwk_oct_new(log, key, key_len);

	rv = (*jwk != NULL);

end:

	if (key)
		oauth2_mem_free(key);

	oauth2_debug(log, "leave");

	return rv;
}

bool oauth2_jose_encrypt(oauth2_log_t *log, const char *secret,
			 const char *s_sig_payload, char **cser)
{
	bool rv = false, rc = false;
	cjose_err err;

	oauth2_jose_jwk_t *jwk = NULL;
	cjose_jws_t *jwt = NULL;
	cjose_jwe_t *jwe = NULL;
	cjose_header_t *sig_hdr = NULL, *enc_hdr = NULL;
	char *s_enc_payload = NULL;

	oauth2_debug(log, "enter");

	if (cser == NULL)
		goto end;

	if (oauth2_jose_jwk_create_symmetric(
		log, secret, OAUTH2_JOSE_OPENSSL_ALG_SHA256, &jwk) == false) {
		oauth2_error(log, "oauth2_jose_jwk_create_symmetric failed");
		goto end;
	}
	oauth2_trace1(log, "hashed symmetric key created: %s",
		      OAUTH2_JOSE_OPENSSL_ALG_SHA256);

	sig_hdr = cjose_header_new(&err);
	if (sig_hdr == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_header_new for signature",
					  err);
		goto end;
	}
	oauth2_trace1(log, "inner header created");

	rc =
	    cjose_header_set(sig_hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_HS256, &err);
	if (rc == false) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(
		    log, "cjose_header_set for signature alg", err);
		goto end;
	}
	oauth2_trace1(log, "inner header \"%s\" set: %s", CJOSE_HDR_ALG,
		      CJOSE_HDR_ALG_HS256);

	jwt = cjose_jws_sign(jwk->jwk, sig_hdr, (const uint8_t *)s_sig_payload,
			     s_sig_payload ? strlen(s_sig_payload) : 0, &err);
	if (jwt == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jws_sign", err);
		goto end;
	}
	oauth2_trace1(log, "inner jwt signed");

	rc = cjose_jws_export(jwt, (const char **)&s_enc_payload, &err);
	if (rc == false) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jws_export", err);
		goto end;
	}
	oauth2_trace1(log, "inner jwt exported: %s", s_enc_payload);

	enc_hdr = cjose_header_new(&err);
	if (enc_hdr == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(
		    log, "cjose_header_new for encryption", err);
		goto end;
	}
	oauth2_trace1(log, "outer header created");

	rc = cjose_header_set(enc_hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_DIR, &err);
	if (rc == false) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(
		    log, "cjose_header_set for encryption alg", err);
		goto end;
	}
	oauth2_trace1(log, "outer header \"%s\" set: %s", CJOSE_HDR_ALG,
		      CJOSE_HDR_ALG_DIR);

	rc = cjose_header_set(enc_hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM,
			      &err);
	if (rc == false) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(
		    log, "cjose_header_set for encryption enc", err);
		goto end;
	}
	oauth2_trace1(log, "outer header \"%s\" set: %s", CJOSE_HDR_ENC,
		      CJOSE_HDR_ENC_A256GCM);

	jwe =
	    cjose_jwe_encrypt(jwk->jwk, enc_hdr, (const uint8_t *)s_enc_payload,
			      strlen(s_enc_payload), &err);
	if (jwt == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jwe_encrypt", err);
		goto end;
	}
	oauth2_trace1(log, "jwe created");

	*cser = cjose_jwe_export(jwe, &err);
	if (*cser == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jwe_export", err);
		goto end;
	}
	oauth2_trace1(log, "jwe exported: %s", *cser);

	rv = true;

end:

	if (jwe)
		cjose_jwe_release(jwe);
	if (jwk)
		oauth2_jose_jwk_release(jwk);
	if (jwt)
		cjose_jws_release(jwt);
	if (sig_hdr)
		cjose_header_release(sig_hdr);
	if (enc_hdr)
		cjose_header_release(enc_hdr);

	oauth2_debug(log, "leave");

	return rv;
}

bool oauth2_jose_jwt_encrypt(oauth2_log_t *log, const char *secret,
			     json_t *payload, char **cser)
{
	bool rc = false;

	char *s_sig_payload = NULL;

	oauth2_debug(log, "enter");

	if (cser == NULL)
		goto end;

	s_sig_payload =
	    payload ? json_dumps(payload, JSON_PRESERVE_ORDER | JSON_COMPACT)
		    : NULL;
	oauth2_trace1(log, "JSON payload serialized: %s", s_sig_payload);

	rc = oauth2_jose_encrypt(log, secret, s_sig_payload, cser);

end:

	if (s_sig_payload)
		oauth2_mem_free(s_sig_payload);

	oauth2_debug(log, "leave");

	return rc;
}

bool oauth2_jose_decrypt(oauth2_log_t *log, const char *secret,
			 const char *cser, char **result)
{
	//	oauth2_debug(log, "enter: JWT header=%s",
	//			oidc_proto_peek_jwt_header(log, cser, NULL));

	bool rv = false, rc = false;
	cjose_err err;

	oauth2_jose_jwk_t *jwk = NULL;
	cjose_jws_t *jwt = NULL;
	cjose_jwe_t *jwe = NULL;

	uint8_t *s_decrypted = NULL, *s_payload = NULL;
	size_t dec_len, payload_len;

	oauth2_debug(log, "enter");

	if (result == NULL)
		goto end;

	if (oauth2_jose_jwk_create_symmetric(
		log, secret, OAUTH2_JOSE_OPENSSL_ALG_SHA256, &jwk) == false) {
		oauth2_error(log, "oauth2_jose_jwk_create_symmetric failed");
		goto end;
	}
	oauth2_trace1(log, "symmetric key created");

	jwe = cjose_jwe_import(cser, cser ? strlen(cser) : 0, &err);
	if (jwe == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jwe_import", err);
		goto end;
	}
	oauth2_trace1(log, "jwe imported");

	s_decrypted = cjose_jwe_decrypt(jwe, jwk->jwk, &dec_len, &err);
	if (s_decrypted == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jwe_decrypt", err);
		goto end;
	}
	oauth2_trace1(log, "jwe decrypted");

	jwt = cjose_jws_import((const char *)s_decrypted, dec_len, &err);
	if (jwt == NULL) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jws_import", err);
		goto end;
	}
	oauth2_trace1(log, "innner jws imported");

	rc = cjose_jws_verify(jwt, jwk->jwk, &err);
	if (rc == false) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jws_verify", err);
		goto end;
	}
	oauth2_trace1(log, "inner jws verified");

	rc = cjose_jws_get_plaintext(jwt, &s_payload, &payload_len, &err);
	if (rc == false) {
		_OAUTH2_UTIL_JOSE_ERR_LOG(log, "cjose_jws_get_plaintext", err);
		goto end;
	}
	oauth2_trace1(log, "plaintext retrieved");

	*result = oauth2_mem_alloc(payload_len + 1);
	strncpy(*result, (const char *)s_payload, payload_len);
	(*result)[payload_len] = '\0';
	oauth2_trace1(log, "plaintext copied");

	rv = true;

end:

	if (s_decrypted)
		oauth2_mem_free(s_decrypted);

	if (jwe)
		cjose_jwe_release(jwe);
	if (jwk)
		oauth2_jose_jwk_release(jwk);
	if (jwt)
		cjose_jws_release(jwt);

	oauth2_debug(log, "leave");

	return rv;
}

bool oauth2_jose_jwt_decrypt(oauth2_log_t *log, const char *secret,
			     const char *cser, json_t **result)
{

	bool rc = false;
	char *payload = NULL;
	json_error_t json_error;

	oauth2_debug(log, "enter");

	if ((secret == NULL) || (cser == NULL) || (result == NULL))
		goto end;

	if (oauth2_jose_decrypt(log, secret, cser, &payload) == false)
		goto end;

	*result = json_loads(payload, 0, &json_error);
	if (*result == NULL) {
		_OAUTH2_JOSE_JANSSON_ERR_LOG(log, "json_loads", json_error);
		goto end;
	}
	oauth2_trace1(log, "payload parsed to JSON");

	rc = true;

end:

	if (payload)
		oauth2_mem_free(payload);

	oauth2_debug(log, "leave");

	return rc;
}

#define OAUTH2_JTI_LENGTH 16

char *oauth2_jwt_create(oauth2_log_t *log, cjose_jwk_t *jwk, const char *alg,
			const char *iss, const char *sub, const char *client_id,
			const char *aud, oauth2_uint_t exp, bool include_iat,
			bool include_jti)
{
	char *rv = NULL;
	char *payload = NULL;
	json_t *assertion = NULL;
	cjose_header_t *hdr = NULL;
	cjose_jws_t *jws = NULL;
	const char *jwt = NULL;
	cjose_err err;
	char *jti = NULL;

	oauth2_debug(log, "enter");

	if (jwk == NULL)
		goto end;

	assertion = json_object();
	if (include_jti) {
		jti = oauth2_rand_str(log, OAUTH2_JTI_LENGTH);
		json_object_set_new(assertion, OAUTH2_CLAIM_JTI,
				    json_string(jti));
	}
	if (iss)
		json_object_set_new(assertion, OAUTH2_CLAIM_ISS,
				    json_string(iss));
	if (sub)
		json_object_set_new(assertion, OAUTH2_CLAIM_SUB,
				    json_string(sub));
	if (aud)
		json_object_set_new(assertion, OAUTH2_CLAIM_AUD,
				    json_string(aud));
	json_object_set_new(assertion, OAUTH2_CLAIM_EXP,
			    json_integer(oauth2_time_now_sec() + exp));
	if (include_iat)
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

	rv = oauth2_strndup(jwt, strlen(jwt));

end:

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

	oauth2_debug(log, "leave");

	return rv;
}

bool oauth2_jose_hash2s(oauth2_log_t *log, const char *digest, const char *src,
			char **dst)
{
	bool rc = false;
	unsigned char *hash_bytes = NULL;
	unsigned int hash_bytes_len = 0;

	if (oauth2_jose_hash_bytes(log, digest, (const unsigned char *)src,
				   strlen(src), &hash_bytes,
				   &hash_bytes_len) == false)
		goto end;

	*dst = _oauth2_bytes2str(log, hash_bytes, hash_bytes_len);

	rc = true;

end:

	if (hash_bytes)
		oauth2_mem_free(hash_bytes);

	return rc;
}

_OAUTH2_CFG_CTX_INIT_START(oauth2_uri_ctx)
ctx->endpoint = NULL;
ctx->cache = NULL;
ctx->expiry_s = OAUTH2_CFG_UINT_UNSET;
_OAUTH2_CFG_CTX_INIT_END

_OAUTH2_CFG_CTX_CLONE_START(oauth2_uri_ctx)
dst->endpoint = oauth2_cfg_endpoint_clone(log, src->endpoint);
dst->cache = src->cache;
dst->expiry_s = src->expiry_s;
_OAUTH2_CFG_CTX_CLONE_END

_OAUTH2_CFG_CTX_FREE_START(oauth2_uri_ctx)
if (ctx->endpoint)
	oauth2_cfg_endpoint_free(log, ctx->endpoint);
_OAUTH2_CFG_CTX_FREE_END

static oauth2_jose_jwk_list_t *oauth2_jose_jwk_list_init(oauth2_log_t *log)
{
	oauth2_jose_jwk_list_t *list =
	    (oauth2_jose_jwk_list_t *)oauth2_mem_alloc(
		sizeof(oauth2_jose_jwk_list_t));
	list->jwk = oauth2_jose_jwk_new();
	list->next = NULL;
	return list;
}

static oauth2_jose_jwk_list_t *
oauth2_jose_jwk_list_clone(oauth2_log_t *log, oauth2_jose_jwk_list_t *src)
{
	oauth2_jose_jwk_list_t *dst = NULL, *ptr = NULL, *last = NULL,
			       *elem = NULL;
	cjose_err err;

	ptr = src;

	while (ptr) {

		elem = oauth2_jose_jwk_list_init(log);
		elem->jwk->kid = oauth2_strdup(ptr->jwk->kid);

		err.code = CJOSE_ERR_NONE;
		elem->jwk->jwk = cjose_jwk_retain(ptr->jwk->jwk, &err);
		if ((elem->jwk->jwk == NULL) && (err.code != CJOSE_ERR_NONE)) {
			oauth2_error(log, "cjose_jwk_retain failed: %s",
				     err.message);
			oauth2_jose_jwk_list_free(log, elem);
			continue;
		}

		if (dst == NULL) {
			dst = elem;
			last = dst;
		} else {
			last->next = elem;
			last = last->next;
		}

		ptr = ptr->next;
	}

	return dst;
}

void oauth2_jose_jwk_list_free(oauth2_log_t *log, oauth2_jose_jwk_list_t *keys)
{
	oauth2_jose_jwk_list_t *ptr = NULL;
	ptr = keys;
	while (ptr) {
		keys = keys->next;
		oauth2_jose_jwk_release(ptr->jwk);
		oauth2_mem_free(ptr);
		ptr = keys;
	}
}

static oauth2_jose_jwk_list_t *
oauth2_jose_jwks_list_resolve(oauth2_log_t *, oauth2_jose_jwks_provider_t *,
			      bool *);
static oauth2_jose_jwk_list_t *
oauth2_jose_jwks_uri_resolve(oauth2_log_t *, oauth2_jose_jwks_provider_t *,
			     bool *);
static oauth2_jose_jwk_list_t *
oauth2_jose_jwks_eckey_url_resolve(oauth2_log_t *,
				   oauth2_jose_jwks_provider_t *, bool *);

static oauth2_jose_jwks_provider_t *
_oauth2_jose_jwks_provider_init(oauth2_log_t *log,
				oauth2_jose_jwks_provider_type_t type)
{
	oauth2_jose_jwks_provider_t *provider =
	    (oauth2_jose_jwks_provider_t *)oauth2_mem_alloc(
		sizeof(oauth2_jose_jwks_provider_t));

	provider->type = type;
	switch (type) {
	case OAUTH2_JOSE_JWKS_PROVIDER_LIST:
		provider->resolve = oauth2_jose_jwks_list_resolve;
		provider->jwks = NULL;
		break;
	case OAUTH2_JOSE_JWKS_PROVIDER_JWKS_URI:
		provider->jwks_uri = oauth2_uri_ctx_init(log);
		provider->resolve = oauth2_jose_jwks_uri_resolve;
		break;
	case OAUTH2_JOSE_JWKS_PROVIDER_ECKEY_URI:
		provider->jwks_uri = oauth2_uri_ctx_init(log);
		provider->resolve = oauth2_jose_jwks_eckey_url_resolve;
		break;
	}

	return provider;
}

static oauth2_jose_jwks_provider_t *
_oauth2_jose_jwks_provider_clone(oauth2_log_t *log,
				 oauth2_jose_jwks_provider_t *src)
{
	oauth2_jose_jwks_provider_t *dst = NULL;

	if (src == NULL)
		goto end;

	dst = (oauth2_jose_jwks_provider_t *)oauth2_mem_alloc(
	    sizeof(oauth2_jose_jwks_provider_t));

	dst->type = src->type;
	dst->resolve = src->resolve;

	switch (src->type) {
	case OAUTH2_JOSE_JWKS_PROVIDER_LIST:
		dst->jwks = oauth2_jose_jwk_list_clone(log, src->jwks);
		break;
	case OAUTH2_JOSE_JWKS_PROVIDER_JWKS_URI:
	case OAUTH2_JOSE_JWKS_PROVIDER_ECKEY_URI:
		dst->jwks_uri = oauth2_uri_ctx_clone(log, src->jwks_uri);
		break;
	}

end:

	return dst;
}

static void
_oauth2_jose_jwks_provider_free(oauth2_log_t *log,
				oauth2_jose_jwks_provider_t *provider)
{

	if (provider == NULL)
		goto end;

	switch (provider->type) {
	case OAUTH2_JOSE_JWKS_PROVIDER_LIST:
		if (provider->jwks)
			oauth2_jose_jwk_list_free(log, provider->jwks);
		break;
	case OAUTH2_JOSE_JWKS_PROVIDER_JWKS_URI:
	case OAUTH2_JOSE_JWKS_PROVIDER_ECKEY_URI:
		if (provider->jwks_uri)
			oauth2_uri_ctx_free(log, provider->jwks_uri);
		break;
	}

	oauth2_mem_free(provider);

end:

	return;
}

oauth2_jose_jwt_validate_claim_t oauth2_parse_validate_claim_option(
    oauth2_log_t *log, const char *value,
    oauth2_jose_jwt_validate_claim_t default_value)
{
	oauth2_jose_jwt_validate_claim_t result = default_value;

	if (value == NULL)
		goto end;

	if (strcasecmp(value, "optional") == 0) {
		result = OAUTH2_JOSE_JWT_VALIDATE_CLAIM_OPTIONAL;
		goto end;
	}

	if (strcasecmp(value, "skip") == 0) {
		result = OAUTH2_JOSE_JWT_VALIDATE_CLAIM_SKIP;
		goto end;
	}

	if (strcasecmp(value, "required") == 0) {
		result = OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED;
		goto end;
	}

end:

	return result;
}

static const char *
_oauth2_validate_claim_option2s(oauth2_jose_jwt_validate_claim_t value)
{
	const char *result = "<undefined>";

	if (value == OAUTH2_JOSE_JWT_VALIDATE_CLAIM_OPTIONAL) {
		result = "optional";
		goto end;
	}

	if (value == OAUTH2_JOSE_JWT_VALIDATE_CLAIM_SKIP) {
		result = "skip";
		goto end;
	}

	if (value == OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED) {
		result = "required";
		goto end;
	}

end:

	return result;
}

#define OAUTH2_JOSE_JWT_IAT_SLACK_DEFAULT (oauth2_uint_t)10

#define OAUTH2_JOSE_JWT_IAT_SLACK_BEFORE "verify.iat.slack_before"
#define OAUTH2_JOSE_JWT_IAT_SLACK_AFTER "verify.iat.slack_after"
#define OAUTH2_JOSE_JWT_ISS_VALIDATE "verify.iss"
#define OAUTH2_JOSE_JWT_EXP_VALIDATE "verify.exp"
#define OAUTH2_JOSE_JWT_IAT_VALIDATE "verify.iat"

_OAUTH2_CFG_CTX_INIT_START(oauth2_jose_jwt_verify_ctx)
ctx->exp_validate = OAUTH2_CFG_UINT_UNSET;
ctx->iat_validate = OAUTH2_CFG_UINT_UNSET;
ctx->iss_validate = OAUTH2_CFG_UINT_UNSET;
ctx->iat_slack_after = OAUTH2_CFG_UINT_UNSET;
ctx->iat_slack_before = OAUTH2_CFG_UINT_UNSET;
ctx->jwks_provider = NULL;
_OAUTH2_CFG_CTX_INIT_END

_OAUTH2_CFG_CTX_CLONE_START(oauth2_jose_jwt_verify_ctx)
dst->exp_validate = src->exp_validate;
dst->iat_slack_after = src->iat_slack_after;
dst->iat_slack_before = src->iat_slack_before;
dst->iat_validate = src->iat_validate;
dst->iss_validate = src->iss_validate;
dst->jwks_provider = _oauth2_jose_jwks_provider_clone(log, src->jwks_provider);
_OAUTH2_CFG_CTX_CLONE_END

_OAUTH2_CFG_CTX_FREE_START(oauth2_jose_jwt_verify_ctx)
if (ctx->jwks_provider)
	_oauth2_jose_jwks_provider_free(log, ctx->jwks_provider);
_OAUTH2_CFG_CTX_FREE_END

_OAUTH2_CFG_CTX_FUNCS(oauth2_jose_jwt_verify_ctx)

bool oauth2_jose_jwt_verify_set_options(
    oauth2_log_t *log, oauth2_jose_jwt_verify_ctx_t *jwt_verify,
    oauth2_jose_jwks_provider_type_t type, const oauth2_nv_list_t *params)
{
	jwt_verify->jwks_provider = _oauth2_jose_jwks_provider_init(log, type);

	jwt_verify->iss_validate = oauth2_parse_validate_claim_option(
	    log, oauth2_nv_list_get(log, params, OAUTH2_JOSE_JWT_ISS_VALIDATE),
	    OAUTH2_JOSE_JWT_VALIDATE_CLAIM_OPTIONAL);
	jwt_verify->exp_validate = oauth2_parse_validate_claim_option(
	    log, oauth2_nv_list_get(log, params, OAUTH2_JOSE_JWT_EXP_VALIDATE),
	    OAUTH2_JOSE_JWT_VALIDATE_CLAIM_OPTIONAL);
	jwt_verify->iat_validate = oauth2_parse_validate_claim_option(
	    log, oauth2_nv_list_get(log, params, OAUTH2_JOSE_JWT_IAT_VALIDATE),
	    OAUTH2_JOSE_JWT_VALIDATE_CLAIM_OPTIONAL);
	// TODO: this is probably different (default -1) for id_token's
	//       would we need to pass all flags explicitly in init?
	jwt_verify->iat_slack_before = oauth2_parse_uint(
	    log,
	    oauth2_nv_list_get(log, params, OAUTH2_JOSE_JWT_IAT_SLACK_BEFORE),
	    OAUTH2_CFG_UINT_UNSET);
	jwt_verify->iat_slack_after = oauth2_parse_uint(
	    log,
	    oauth2_nv_list_get(log, params, OAUTH2_JOSE_JWT_IAT_SLACK_AFTER),
	    OAUTH2_JOSE_JWT_IAT_SLACK_DEFAULT);

	// TODO: calculate rc based on previous calls
	return true;
}

typedef struct oauth2_jose_jwt_verify_jwk_ctx_t {
	cjose_jws_t *jws;
	const char *kid;
	bool verified;
} oauth2_jose_jwt_verify_jwk_ctx_t;

static bool _oauth2_jose_jwt_verify_jwk(oauth2_log_t *log, void *rec,
					const char *kid,
					const oauth2_jose_jwk_t *jwk)
{
	bool rc = true;
	cjose_err err;

	oauth2_jose_jwt_verify_jwk_ctx_t *ctx =
	    (oauth2_jose_jwt_verify_jwk_ctx_t *)rec;

	oauth2_debug(log, "enter: jws kid=%s, jwk kid=%s", ctx->kid, kid);

	if ((ctx == NULL) || (jwk == NULL))
		goto end;

	// NB: kid can be ""
	if ((ctx->kid != NULL) && (kid != NULL) && (strcmp(kid, "") != 0) &&
	    (strcmp(ctx->kid, kid) != 0))
		goto end;

	if (cjose_jws_verify(ctx->jws, jwk->jwk, &err) == true) {
		oauth2_debug(log, "cjose_jws_verify returned true");
		ctx->verified = true;
		// break the loop
		rc = false;
	}

end:

	oauth2_debug(log, "leave: rc=%d", rc == false);

	return rc;
}

char *oauth2_jose_jwt_header_peek(oauth2_log_t *log,
				  const char *compact_encoded_jwt,
				  const char **alg)
{
	char *input = NULL, *result = NULL;
	json_t *json = NULL;
	char *p = NULL;
	size_t result_len;
	char *rv = NULL;

	if (compact_encoded_jwt == NULL)
		goto end;

	p = strstr(compact_encoded_jwt, ".");
	if (p == NULL)
		goto end;

	input = oauth2_strndup(compact_encoded_jwt,
			       strlen(compact_encoded_jwt) - strlen(p));

	oauth2_debug(log, "decoding: %s (%d-%d=%d)", input,
		     strlen(compact_encoded_jwt), strlen(p),
		     strlen(compact_encoded_jwt) - strlen(p));

	if (oauth2_base64url_decode(log, input, (uint8_t **)&result,
				    &result_len) == false)
		goto end;

	rv = oauth2_strndup(result, result_len);

	oauth2_debug(log, "decoded: %s", rv);

	if (oauth2_json_decode_object(log, rv, &json) == false) {
		oauth2_mem_free(rv);
		rv = NULL;
		goto end;
	}

	if ((json == NULL) || (alg == NULL))
		goto end;

	*alg = json_string_value(json_object_get(json, CJOSE_HDR_ALG));

end:

	if (input)
		oauth2_mem_free(input);
	if (result)
		oauth2_mem_free(result);
	if (json)
		json_decref(json);

	return rv;
}

typedef bool(oauth2_jose_verification_keys_loop_cb_t)(
    oauth2_log_t *log, void *rec, const char *kid,
    const oauth2_jose_jwk_t *jwk);

static void _oauth2_jose_verification_keys_loop(
    oauth2_log_t *log, const oauth2_jose_jwk_list_t *list,
    oauth2_jose_verification_keys_loop_cb_t *callback, void *rec)
{
	const oauth2_jose_jwk_list_t *ptr = NULL;

	if ((list == NULL) || (callback == NULL))
		goto end;

	for (ptr = list; ptr; ptr = ptr->next) {
		if (callback(log, rec, ptr->jwk->kid, ptr->jwk) == false)
			break;
	}

end:

	return;
}

static bool
_oauth2_jose_jwt_validate_iss(oauth2_log_t *log, const json_t *json_payload,
			      const char *iss,
			      oauth2_jose_jwt_validate_claim_t validate)
{
	bool rc = false;
	char *value = NULL;

	oauth2_debug(log, "enter: iss=%s, validate=%s", iss,
		     _oauth2_validate_claim_option2s(validate));

	if (validate == OAUTH2_JOSE_JWT_VALIDATE_CLAIM_SKIP) {
		rc = true;
		goto end;
	}

	if (iss == NULL) {
		rc = (validate != OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);
		goto end;
	}

	if (oauth2_json_string_get(log, json_payload, OAUTH2_JOSE_JWT_ISS,
				   &value, NULL) == false) {
		rc = (validate != OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);
		goto end;
	}

	if (value == NULL) {
		oauth2_error(log,
			     "JWT did not contain an \"%s\" string (requested "
			     "value: %s)",
			     OAUTH2_JOSE_JWT_ISS, iss);
		rc = (validate != OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);
		goto end;
	}

	if (strcmp(iss, value) != 0) {
		oauth2_error(log,
			     "requested issuer (%s) does not match received "
			     "\"%s\" value in id_token (%s)",
			     iss, OAUTH2_JOSE_JWT_ISS, value);
		goto end;
	}

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool
_oauth2_jose_jwt_validate_exp(oauth2_log_t *log, const json_t *json_payload,
			      oauth2_jose_jwt_validate_claim_t validate)
{
	bool rc = false;
	json_int_t exp = -1;
	oauth2_time_t now;

	oauth2_debug(log, "enter: validate=%s",
		     _oauth2_validate_claim_option2s(validate));

	if (validate == OAUTH2_JOSE_JWT_VALIDATE_CLAIM_SKIP) {
		rc = true;
		goto end;
	}

	if (oauth2_json_number_get(log, json_payload, OAUTH2_JOSE_JWT_EXP, &exp,
				   -1) == false) {
		rc = (validate != OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);
		goto end;
	}

	if (exp == -1) {
		oauth2_warn(log, "JWT did not contain a \"%s\" number",
			    OAUTH2_JOSE_JWT_EXP);
		rc = (validate != OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);
		goto end;
	}

	now = oauth2_time_now_sec();

	oauth2_debug(log,
		     "\"%s\"=%" JSON_INTEGER_FORMAT ", %ld seconds from now",
		     OAUTH2_JOSE_JWT_EXP, exp, (long)(exp - now));

	if (now > exp) {
		oauth2_error(log,
			     "\"%s\" validation failure (%ld): JWT expired %ld "
			     "seconds ago",
			     OAUTH2_JOSE_JWT_EXP, (long)exp, (long)(now - exp));
		goto end;
	}

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_jose_jwt_validate_iat(oauth2_log_t *log, const json_t *json_payload,
				  oauth2_jose_jwt_validate_claim_t validate,
				  oauth2_uint_t slack_before,
				  oauth2_uint_t slack_after)
{
	bool rc = false;
	json_int_t iat = -1;
	oauth2_time_t now;

	oauth2_debug(log,
		     "enter: validate=%s, slack_before=" OAUTH2_UINT_FORMAT
		     ", slack_after=" OAUTH2_UINT_FORMAT,
		     _oauth2_validate_claim_option2s(validate), slack_before,
		     slack_after);

	if (validate == OAUTH2_JOSE_JWT_VALIDATE_CLAIM_SKIP) {
		rc = true;
		goto end;
	}

	if (oauth2_json_number_get(log, json_payload, OAUTH2_JOSE_JWT_IAT, &iat,
				   -1) == false) {
		rc = (validate != OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);
		goto end;
	}

	if (iat == -1) {
		oauth2_warn(log, "JWT did not contain a \"%s\" number",
			    OAUTH2_JOSE_JWT_IAT);
		rc = (validate != OAUTH2_JOSE_JWT_VALIDATE_CLAIM_REQUIRED);
		goto end;
	}

	now = oauth2_time_now_sec();

	if ((slack_before != OAUTH2_CFG_UINT_UNSET) &&
	    ((now - slack_before) > iat)) {
		oauth2_error(log,
			     "\"%s\" validation failure (%ld): JWT was issued "
			     "more than %d seconds ago",
			     OAUTH2_JOSE_JWT_IAT, (long)iat, slack_before);
		goto end;
	}

	if ((slack_after != OAUTH2_CFG_UINT_UNSET) &&
	    ((now + slack_after) < iat)) {
		oauth2_error(log,
			     "\"%s\" validation failure (%ld): JWT was issued "
			     "more than %d seconds in the future",
			     OAUTH2_JOSE_JWT_IAT, (long)iat, slack_after);
		goto end;
	}

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool
_oauth2_jose_jwt_payload_validate(oauth2_log_t *log,
				  oauth2_jose_jwt_verify_ctx_t *jwt_verify_ctx,
				  const json_t *json_payload, const char *iss)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	if (_oauth2_jose_jwt_validate_iss(
		log, json_payload, iss, jwt_verify_ctx->iss_validate) == false)
		goto end;

	if (_oauth2_jose_jwt_validate_exp(
		log, json_payload, jwt_verify_ctx->exp_validate) == false)
		goto end;

	if (oauth2_jose_jwt_validate_iat(
		log, json_payload, jwt_verify_ctx->iat_validate,
		jwt_verify_ctx->iat_slack_before,
		jwt_verify_ctx->iat_slack_after) == false)
		goto end;

	// TODO: token_binding_policy
	//	if (oauth2_jose_jwt_validate_cnf(r, jwt->payload.value.json,
	//			token_binding_policy) == false)
	//		goto end;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_jose_jwt_verify(oauth2_log_t *log,
			    oauth2_jose_jwt_verify_ctx_t *jwt_verify_ctx,
			    const char *token, json_t **json_payload,
			    char **s_payload)
{
	bool rc = false;
	char *peek = NULL;
	cjose_jws_t *jws = NULL;
	cjose_header_t *hdr = NULL;
	cjose_err err;
	oauth2_jose_jwk_list_t *keys = NULL;
	oauth2_jose_jwt_verify_jwk_ctx_t ctx;
	uint8_t *plaintext = NULL;
	size_t plaintext_len = 0;
	bool refresh = false;

	peek = oauth2_jose_jwt_header_peek(log, token, NULL);
	oauth2_debug(log, "enter: JWT token header=%s", peek);

	if (token == NULL)
		goto end;

	/*
	 * TODO: resolve the shared secret(s) and the private key(s) for
	 * decryption
	 */

	// TODO: this is not optimized anymore across different JWK verify
	// configs

	jws = cjose_jws_import(token, strlen(token), &err);
	if (jws == NULL) {
		oauth2_error(log, "cjose_jws_import failed: %s", err.message);
		goto end;
	}

	hdr = cjose_jws_get_protected(jws);
	if (hdr == NULL)
		goto end;

	if (jwt_verify_ctx) {

		keys = jwt_verify_ctx->jwks_provider->resolve(
		    log, jwt_verify_ctx->jwks_provider, &refresh);

		ctx.jws = jws;
		ctx.kid = cjose_header_get(hdr, "kid", &err);
		ctx.verified = false;

		_oauth2_jose_verification_keys_loop(
		    log, keys, _oauth2_jose_jwt_verify_jwk, &ctx);

		if (ctx.verified == false) {

			if (refresh == false)
				goto end;

			if (keys)
				oauth2_jose_jwk_list_free(log, keys);
			keys = jwt_verify_ctx->jwks_provider->resolve(
			    log, jwt_verify_ctx->jwks_provider, &refresh);
			_oauth2_jose_verification_keys_loop(
			    log, keys, _oauth2_jose_jwt_verify_jwk, &ctx);

			if (ctx.verified == false)
				goto end;
		}
	}

	if (cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err) ==
	    false) {
		oauth2_error(log, "cjose_jws_get_plaintext failed: %s",
			     err.message);
		goto end;
	}

	if ((s_payload == NULL) || (json_payload == NULL))
		goto end;

	*s_payload = oauth2_strndup((const char *)plaintext, plaintext_len);

	oauth2_debug(log, "got plaintext (len=%lu): %s", plaintext_len,
		     *s_payload);

	if (oauth2_json_decode_object(log, *s_payload, json_payload) == false) {
		oauth2_mem_free(*s_payload);
		*s_payload = NULL;
		goto end;
	}

	if (jwt_verify_ctx) {
		if (_oauth2_jose_jwt_payload_validate(
			log, jwt_verify_ctx, *json_payload, NULL) == false) {
			json_decref(*json_payload);
			*json_payload = NULL;
			oauth2_mem_free(*s_payload);
			*s_payload = NULL;
			goto end;
		}
	}

	rc = true;

end:

	if (peek)
		oauth2_mem_free(peek);
	if (jws)
		cjose_jws_release(jws);
	if (keys)
		oauth2_jose_jwk_list_free(log, keys);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _oauth2_jose_jwt_verify_callback(oauth2_log_t *log,
					     oauth2_cfg_token_verify_t *verify,
					     const char *token,
					     json_t **json_payload,
					     char **s_payload)
{
	bool rc = false;
	oauth2_jose_jwt_verify_ctx_t *ctx = NULL;

	oauth2_debug(log, "enter");

	if ((verify == NULL) || (verify->ctx == NULL) ||
	    (verify->ctx->ptr == NULL))
		goto end;

	ctx = (oauth2_jose_jwt_verify_ctx_t *)verify->ctx->ptr;
	rc = oauth2_jose_jwt_verify(log, ctx, token, json_payload, s_payload);
	if (rc == false)
		goto end;

end:

	return rc;
}

static char *
_oauth2_jose_verify_options_jwk_add_jwk(oauth2_log_t *log, cjose_jwk_t *jwk,
					const oauth2_nv_list_t *params,
					oauth2_cfg_token_verify_t *verify)
{
	char *rv = NULL;
	oauth2_jose_jwt_verify_ctx_t *ptr = NULL;
	const char *kid = NULL;
	cjose_err err;

	verify->callback = _oauth2_jose_jwt_verify_callback;
	verify->ctx->callbacks = &oauth2_jose_jwt_verify_ctx_funcs;
	verify->ctx->ptr = verify->ctx->callbacks->init(log);
	ptr = (oauth2_jose_jwt_verify_ctx_t *)verify->ctx->ptr;

	if (oauth2_jose_jwt_verify_set_options(
		log, ptr, OAUTH2_JOSE_JWKS_PROVIDER_LIST, params) == false) {
		rv = oauth2_strdup("oauth2_jose_jwt_verify_set_options failed");
		goto end;
	}

	// set or possibly override kid in JWK
	kid = oauth2_nv_list_get(log, params, "kid");
	if (kid) {
		if (cjose_jwk_set_kid(jwk, kid, strlen(kid), &err) == false) {
			rv = oauth2_stradd(NULL, "cjose_jwk_set_kid failed",
					   ": ", err.message);
			goto end;
		}
	} else {
		err.code = CJOSE_ERR_NONE;
		kid = cjose_jwk_get_kid(jwk, &err);
		if ((kid == NULL) && (err.code != CJOSE_ERR_NONE)) {
			rv = oauth2_stradd(NULL, "cjose_jwk_get_kid failed",
					   ": ", err.message);
			goto end;
		}
	}

	// list of one
	ptr->jwks_provider->jwks = oauth2_jose_jwk_list_init(log);
	ptr->jwks_provider->jwks->jwk->jwk = jwk;
	ptr->jwks_provider->jwks->jwk->kid = kid ? oauth2_strdup(kid) : NULL;
	ptr->jwks_provider->jwks->next = NULL;

end:

	return rv;
}

static char *_oauth2_jose_verify_options_jwk_set_symmetric_key(
    oauth2_log_t *log, const uint8_t *key, size_t key_len,
    const oauth2_nv_list_t *params, oauth2_cfg_token_verify_t *verify)
{
	char *rv = NULL;
	cjose_err err;
	cjose_jwk_t *jwk = NULL;

	jwk = cjose_jwk_create_oct_spec(key, key_len, &err);
	if (jwk == NULL) {
		rv = oauth2_stradd(NULL, "cjose_jwk_create_oct_spec failed",
				   ": ", err.message);
		goto end;
	}

	rv = _oauth2_jose_verify_options_jwk_add_jwk(log, jwk, params, verify);

end:

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_plain)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;

	char *rv = NULL;
	const uint8_t *key = NULL;
	size_t key_len = 0;

	if (value == NULL) {
		rv = oauth2_strdup("no plain symmetric key value provided");
		goto end;
	}

	key = (const uint8_t *)value;
	key_len = strlen(value);

	rv = _oauth2_jose_verify_options_jwk_set_symmetric_key(
	    log, key, key_len, params, verify);

end:

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_base64)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;

	char *rv = NULL;
	uint8_t *key = NULL;
	size_t key_len = 0;

	if (value == NULL) {
		rv = oauth2_strdup(
		    "no base64 encoded symmetric key value provided");
		goto end;
	}

	if (oauth2_base64_decode(log, value, &key, &key_len) == false) {
		rv = oauth2_strdup("oauth2_base64_decode failed");
		goto end;
	}

	rv = _oauth2_jose_verify_options_jwk_set_symmetric_key(
	    log, key, key_len, params, verify);

end:

	if (key)
		oauth2_mem_free(key);

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_base64url)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;

	char *rv = NULL;
	uint8_t *key = NULL;
	size_t key_len = 0;

	if (value == NULL) {
		rv = oauth2_strdup(
		    "no base64url encoded symmetric key value provided");
		goto end;
	}

	if (oauth2_base64url_decode(log, value, &key, &key_len) == false) {
		rv = oauth2_strdup("oauth2_base64url_decode failed");
		goto end;
	}

	rv = _oauth2_jose_verify_options_jwk_set_symmetric_key(
	    log, key, key_len, params, verify);

end:

	if (key)
		oauth2_mem_free(key);

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_hex)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;

	char *rv = NULL;
	unsigned char *key = NULL;
	size_t key_len = 0;
	const char *ptr = NULL;
	size_t n = 0;

	if (value == NULL) {
		rv = oauth2_strdup("no hex symmetric key value provided");
		goto end;
	}

	key_len = strlen(value) / 2;
	ptr = value;
	key = oauth2_mem_alloc(key_len);
	for (n = 0; n < key_len / sizeof(unsigned char); n++) {
		if (sscanf(ptr, "%2hhx", &key[n]) != 1) {
			rv = oauth2_strdup("sscanf failed");
			goto end;
		}
		ptr += 2;
	}

	rv = _oauth2_jose_verify_options_jwk_set_symmetric_key(
	    log, (const uint8_t *)key, key_len, params, verify);

end:

	if (key)
		oauth2_mem_free(key);

	return rv;
}

static BIO *_oauth2_jose_str2bio(oauth2_log_t *log, const char *value)
{
	BIO *input = NULL;

	if ((input = BIO_new(BIO_s_mem())) == NULL) {
		oauth2_error(log, "BIO allocation failed: %s",
			     ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	if (BIO_puts(input, value) <= 0) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "BIO_puts");
		goto end;
	}

end:

	return input;
}

static char *
_oauth2_jose_options_jwk_set_rsa_key(oauth2_log_t *log, EVP_PKEY *pkey,
				     const oauth2_nv_list_t *params,
				     oauth2_cfg_token_verify_t *verify)
{
	char *rv = NULL;
	cjose_jwk_rsa_keyspec key_spec;
	cjose_err err;
	cjose_jwk_t *jwk = NULL;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL;

	memset(&key_spec, 0, sizeof(cjose_jwk_rsa_keyspec));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &rsa_n);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &rsa_e);
#else
	RSA *rsa = (RSA *)EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		rv = oauth2_stradd(NULL, "EVP_PKEY_get1_RSA failed", ": ",
				   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	RSA_get0_key(rsa, (const BIGNUM **)&rsa_n, (const BIGNUM **)&rsa_e,
		     NULL);
#else
	rsa_n = rsa->n;
	rsa_e = rsa->e;
#endif

	RSA_free(rsa);
#endif

	key_spec.nlen = BN_num_bytes(rsa_n);
	key_spec.n = oauth2_mem_alloc(key_spec.nlen);
	BN_bn2bin(rsa_n, key_spec.n);

	key_spec.elen = BN_num_bytes(rsa_e);
	key_spec.e = oauth2_mem_alloc(key_spec.elen);
	BN_bn2bin(rsa_e, key_spec.e);

	jwk = cjose_jwk_create_RSA_spec(&key_spec, &err);
	if (jwk == NULL) {
		rv = oauth2_stradd(NULL, "cjose_jwk_create_RSA_spec failed",
				   ": ", err.message);
		goto end;
	}

	rv = _oauth2_jose_verify_options_jwk_add_jwk(log, jwk, params, verify);

end:

	if (key_spec.n)
		oauth2_mem_free(key_spec.n);
	if (key_spec.e)
		oauth2_mem_free(key_spec.e);

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_pem)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;

	char *rv = NULL;
	BIO *input = NULL;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;

	input = _oauth2_jose_str2bio(log, value);
	if (input == NULL) {
		rv = oauth2_stradd(NULL, "_oauth2_jose_str2bio failed", ": ",
				   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	x509 = PEM_read_bio_X509_AUX(input, NULL, NULL, NULL);
	if (x509 == NULL) {
		rv = oauth2_stradd(NULL, "PEM_read_bio_X509_AUX failed", ": ",
				   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		rv = oauth2_stradd(NULL, "X509_get_pubkey failed", ": ",
				   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	rv = _oauth2_jose_options_jwk_set_rsa_key(log, pkey, params, verify);

end:

	if (x509)
		X509_free(x509);
	if (pkey)
		EVP_PKEY_free(pkey);

	if (input)
		BIO_free(input);

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_pubkey)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;

	char *rv = NULL;
	BIO *input = NULL;
	EVP_PKEY *pkey = NULL;

	input = _oauth2_jose_str2bio(log, value);
	if (input == NULL) {
		rv = oauth2_stradd(NULL, "_oauth2_jose_str2bio failed", ": ",
				   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	pkey = PEM_read_bio_PUBKEY(input, &pkey, NULL, NULL);
	if (pkey == NULL) {
		rv = oauth2_stradd(NULL, "PEM_read_bio_PUBKEY failed", ": ",
				   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	rv = _oauth2_jose_options_jwk_set_rsa_key(log, pkey, params, verify);

end:

	if (pkey)
		EVP_PKEY_free(pkey);
	if (input)
		BIO_free(input);

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_jwk)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;

	char *rv = NULL;
	cjose_jwk_t *jwk = NULL;
	cjose_err err;

	jwk = cjose_jwk_import(value, strlen(value), &err);
	if (jwk == NULL) {
		rv = oauth2_stradd(NULL, "cjose_jwk_import failed", ": ",
				   err.message);
		goto end;
	}

	rv = _oauth2_jose_verify_options_jwk_add_jwk(log, jwk, params, verify);

end:

	return rv;
}

#define OAUTH2_JOSE_URI_REFRESH_DEFAULT 60 * 60 * 24

char *oauth2_jose_options_uri_ctx(oauth2_log_t *log, const char *value,
				  const oauth2_nv_list_t *params,
				  oauth2_uri_ctx_t *ctx, const char *prefix)
{
	char *rv = NULL;
	char *key = NULL;

	ctx->endpoint = oauth2_cfg_endpoint_init(log);
	rv = oauth2_cfg_set_endpoint(log, ctx->endpoint, value, params, prefix);

	key = oauth2_stradd(NULL, prefix, ".", "cache");
	ctx->cache =
	    oauth2_cache_obtain(log, oauth2_nv_list_get(log, params, key));
	oauth2_mem_free(key);
	if (ctx->cache == NULL)
		rv = oauth2_strdup("cache could not be found");

	key = oauth2_stradd(NULL, prefix, ".", "expiry");
	ctx->expiry_s =
	    oauth2_parse_uint(log, oauth2_nv_list_get(log, params, key),
			      OAUTH2_JOSE_URI_REFRESH_DEFAULT);
	oauth2_mem_free(key);

	return rv;
}

static char *_oauth2_jose_verify_options_jwk_set_url(
    oauth2_log_t *log, const char *value, const oauth2_nv_list_t *params,
    oauth2_cfg_token_verify_t *verify, oauth2_jose_jwks_provider_type_t type,
    const char *prefix)
{
	char *rv = NULL;
	oauth2_jose_jwt_verify_ctx_t *ptr = NULL;

	oauth2_debug(log, "enter");

	verify->callback = _oauth2_jose_jwt_verify_callback;
	verify->ctx->callbacks = &oauth2_jose_jwt_verify_ctx_funcs;
	verify->ctx->ptr = verify->ctx->callbacks->init(log);
	ptr = (oauth2_jose_jwt_verify_ctx_t *)verify->ctx->ptr;

	if (oauth2_jose_jwt_verify_set_options(log, ptr, type, params) ==
	    false) {
		rv = oauth2_strdup("oauth2_jose_jwt_verify_set_options failed");
		goto end;
	}

	rv = oauth2_jose_options_uri_ctx(log, value, params,
					 ptr->jwks_provider->jwks_uri, prefix);

end:

	oauth2_debug(log, "leave: %s", rv);

	return rv;
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_jwks_uri)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;
	return _oauth2_jose_verify_options_jwk_set_url(
	    log, value, params, verify, OAUTH2_JOSE_JWKS_PROVIDER_JWKS_URI,
	    "jwks_uri");
}

_OAUTH_CFG_CTX_CALLBACK(oauth2_jose_verify_options_jwk_set_eckey_uri)
{
	oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)ctx;
	return _oauth2_jose_verify_options_jwk_set_url(
	    log, value, params, verify, OAUTH2_JOSE_JWKS_PROVIDER_ECKEY_URI,
	    "eckey_uri");
}

static oauth2_jose_jwk_list_t *oauth2_jose_jwks_list_resolve(
    oauth2_log_t *log, oauth2_jose_jwks_provider_t *provider, bool *refresh)
{
	*refresh = false;
	return oauth2_jose_jwk_list_clone(log, provider->jwks);
}

typedef oauth2_jose_jwk_list_t *(oauth2_jose_jwks_url_resolve_response_cb_t)(
    oauth2_log_t *log, char *response);

// cater for the (Amazon ALB) use case that only a single EC(!) key is served
// from the URL
static oauth2_jose_jwk_list_t *
_oauth2_jose_jwks_eckey_url_resolve_response_callback(oauth2_log_t *log,
						      char *response)
{
	oauth2_jose_jwk_list_t *keys = NULL;
	BIGNUM *x = NULL, *y = NULL;
	cjose_jwk_ec_keyspec spec;
	cjose_jwk_t *jwk = NULL;
	cjose_err err;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OSSL_DECODER_CTX *dctx = NULL;
	EVP_PKEY *pkey = NULL;
	const unsigned char *data = (unsigned char *)response;
	size_t datalen = strlen(response) + 1;

	dctx = OSSL_DECODER_CTX_new_for_pkey(
	    &pkey, "PEM", NULL, "EC",
	    OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
		OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
	    NULL, NULL);
	if (dctx == NULL) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log,
					     "OSSL_DECODER_CTX_new_for_pkey");
		goto end;
	}

	if (OSSL_DECODER_from_data(dctx, &data, &datalen) <= 0) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "OSSL_DECODER_from_data");
		goto end;
	}

	char *curve_name[64];
	size_t len = 0;
	if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
					   (char *)curve_name,
					   sizeof(curve_name), &len) <= 0) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log,
					     "EVP_PKEY_get_utf8_string_param");
		goto end;
	}

	spec.crv = OBJ_txt2nid((char *)curve_name);
	if (spec.crv == NID_undef) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "OBJ_txt2nid");
		goto end;
	}

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) <= 0) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "EVP_PKEY_get_bn_param");
		goto end;
	}

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) <= 0) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "EVP_PKEY_get_bn_param");
		goto end;
	}

#else
	BIO *input = NULL;
	EC_KEY *eckey = NULL;
	const EC_GROUP *ecgroup = NULL;
	const EC_POINT *ecpoint = NULL;

	input = _oauth2_jose_str2bio(log, response);
	if (input == NULL)
		goto end;

	eckey = PEM_read_bio_EC_PUBKEY(input, NULL, 0, 0);
	if (eckey == NULL) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "PEM_read_bio_EC_PUBKEY");
		goto end;
	}

	ecgroup = EC_KEY_get0_group(eckey);
	if (ecgroup == NULL) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "EC_KEY_get0_group");
		goto end;
	}

	spec.crv = EC_GROUP_get_curve_name(ecgroup);
	if (spec.crv == 0) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "EC_GROUP_get_curve_name");
		goto end;
	}

	ecpoint = EC_KEY_get0_public_key(eckey);
	if (ecpoint == 0) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "EC_KEY_get0_public_key");
		goto end;
	}

	x = BN_new();
	y = BN_new();
	if ((x == NULL) || (y == NULL)) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(log, "BN_new");
		goto end;
	}

	if (EC_POINT_get_affine_coordinates_GFp(ecgroup, ecpoint, x, y, NULL) !=
	    1) {
		_OAUTH2_JOSE_OPENSSL_ERR_LOG(
		    log, "EC_POINT_get_affine_coordinates_GFp");
		goto end;
	}
#endif

	spec.xlen = BN_num_bytes(x);
	spec.x = oauth2_mem_alloc(spec.xlen);
	BN_bn2bin(x, spec.x);

	spec.ylen = BN_num_bytes(y);
	spec.y = oauth2_mem_alloc(spec.ylen);
	BN_bn2bin(y, spec.y);

	spec.dlen = 0;
	spec.d = NULL;

	err.code = CJOSE_ERR_NONE;
	jwk = cjose_jwk_create_EC_spec(&spec, &err);
	if ((jwk == NULL) || (err.code != CJOSE_ERR_NONE)) {
		oauth2_error(log, "cjose_jwk_create_EC_spec failed: %s",
			     err.message);
		goto end;
	}

	keys = oauth2_jose_jwk_list_init(log);
	keys->jwk->jwk = jwk;
	keys->jwk->kid = NULL;

end:

	if (spec.x)
		oauth2_mem_free(spec.x);
	if (spec.y)
		oauth2_mem_free(spec.y);

	if (x)
		BN_free(x);
	if (y)
		BN_free(y);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (dctx)
		OSSL_DECODER_CTX_free(dctx);
#else
	if (eckey)
		EC_KEY_free(eckey);

	if (input)
		BIO_free(input);
#endif

	return keys;
}

static oauth2_jose_jwk_list_t *
_oauth2_jose_jwks_uri_resolve_response_callback(oauth2_log_t *log,
						char *response)
{
	json_t *json_result = NULL, *json_keys = NULL, *json_key = NULL;
	oauth2_jose_jwk_list_t *result = NULL, *elem = NULL, *last = NULL;
	int i = 0;
	cjose_err err;

	if (oauth2_json_decode_object(log, response, &json_result) == false)
		goto end;

	// TODO: #define
	json_keys = json_object_get(json_result, "keys");
	if ((json_keys == NULL) || !(json_is_array(json_keys))) {
		oauth2_error(log, "\"keys\" array element is not a JSON array");
		goto end;
	}

	for (i = 0; i < json_array_size(json_keys); i++) {

		json_key = json_array_get(json_keys, i);

		// TODO: #define
		const char *use =
		    json_string_value(json_object_get(json_key, "use"));
		if ((use != NULL) && (strcmp(use, "sig") != 0)) {
			oauth2_debug(log,
				     "skipping key because of "
				     "non-matching \"%s\": \"%s\"",
				     "use", use);
			continue;
		}

		// TODO: search/skip based on key type (?)

		elem = oauth2_jose_jwk_list_init(log);
		err.code = CJOSE_ERR_NONE;

		elem->jwk->jwk = cjose_jwk_import_json(json_key, &err);
		if ((elem->jwk->jwk == NULL) || (err.code != CJOSE_ERR_NONE)) {
			oauth2_warn(log, "cjose_jwk_import_json failed", ": ",
				    err.message);
			oauth2_jose_jwk_list_free(log, elem);
			continue;
		}

		elem->jwk->kid =
		    oauth2_strdup(cjose_jwk_get_kid(elem->jwk->jwk, &err));
		if (err.code != CJOSE_ERR_NONE) {
			oauth2_warn(log, "cjose_jwk_get_kid failed", ": ",
				    err.message);
			oauth2_jose_jwk_list_free(log, elem);
			continue;
		}

		if (result == NULL) {
			result = elem;
			last = result;
		} else {
			last->next = elem;
			last = last->next;
		}
	}

end:

	if (json_result)
		json_decref(json_result);

	return result;
}

char *oauth2_jose_resolve_from_uri(oauth2_log_t *log, oauth2_uri_ctx_t *uri_ctx,
				   bool *refresh)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	char *response = NULL;
	oauth2_uint_t status_code = 0;

	oauth2_debug(log, "enter");

	if (uri_ctx == NULL)
		goto end;

	if (*refresh == false) {

		oauth2_cache_get(log, uri_ctx->cache,
				 oauth2_cfg_endpoint_get_url(uri_ctx->endpoint),
				 &response);

		*refresh = true;
	}

	if (response == NULL) {

		*refresh = false;

		ctx = oauth2_http_call_ctx_init(log);
		oauth2_http_call_ctx_ssl_verify_set(
		    log, ctx,
		    oauth2_cfg_endpoint_get_ssl_verify(uri_ctx->endpoint));
		oauth2_http_call_ctx_outgoing_proxy_set(
		    log, ctx,
		    oauth2_cfg_endpoint_get_outgoing_proxy(uri_ctx->endpoint));

		rc = oauth2_http_get(
		    log, oauth2_cfg_endpoint_get_url(uri_ctx->endpoint), NULL,
		    ctx, &response, &status_code);
		if (rc == false)
			goto end;

		if ((status_code < 200) || (status_code >= 300)) {
			rc = false;
			goto end;
		}

		oauth2_cache_set(log, uri_ctx->cache,
				 oauth2_cfg_endpoint_get_url(uri_ctx->endpoint),
				 response, uri_ctx->expiry_s);
	}

end:

	if (ctx)
		oauth2_http_call_ctx_free(log, ctx);

	oauth2_debug(log, "leave: %s", response);

	return response;
}

static oauth2_jose_jwk_list_t *_oauth2_jose_jwks_resolve_from_uri(
    oauth2_log_t *log, oauth2_jose_jwks_provider_t *provider, bool *refresh,
    oauth2_jose_jwks_url_resolve_response_cb_t *resolve_response_cb)
{

	oauth2_jose_jwk_list_t *dst = NULL;
	char *response = NULL;

	response =
	    oauth2_jose_resolve_from_uri(log, provider->jwks_uri, refresh);
	if (response == NULL)
		goto end;

	dst = resolve_response_cb(log, response);

end:

	if (response)
		oauth2_mem_free(response);

	return dst;
}

static oauth2_jose_jwk_list_t *oauth2_jose_jwks_uri_resolve(
    oauth2_log_t *log, oauth2_jose_jwks_provider_t *provider, bool *refresh)
{
	return _oauth2_jose_jwks_resolve_from_uri(
	    log, provider, refresh,
	    _oauth2_jose_jwks_uri_resolve_response_callback);
}

static oauth2_jose_jwk_list_t *oauth2_jose_jwks_eckey_url_resolve(
    oauth2_log_t *log, oauth2_jose_jwks_provider_t *provider, bool *refresh)
{
	return _oauth2_jose_jwks_resolve_from_uri(
	    log, provider, refresh,
	    _oauth2_jose_jwks_eckey_url_resolve_response_callback);
}

/*
oauth2_jose_jwk_list_t *
oauth2_jose_jwks_resolve(oauth2_log_t *log, oauth2_cfg_token_verify_t *verify,
			 bool *refresh)
{
	// oauth2_jose_jwk_list_t *list = NULL, *last = NULL;
	oauth2_jose_jwt_verify_ctx_t *ptr = NULL;
	oauth2_jose_jwk_list_t *jwks = NULL;

	oauth2_debug(log, "enter");

	if ((verify == NULL) || (verify->ctx == NULL))
		goto end;

	ptr = (oauth2_jose_jwt_verify_ctx_t *)verify->ctx->ptr;
	jwks = ptr->jwks_provider->resolve(log, ptr->jwks_provider, refresh);

end:

	oauth2_debug(log, "leave: %p", jwks);

	return jwks;
}
*/

bool oauth2_jose_jwk_thumbprint(oauth2_log_t *log, const cjose_jwk_t *jwk,
				unsigned char **hash_bytes,
				unsigned int *hash_bytes_len)
{
	bool rc = false;
	char *s_payload = NULL, *s_compact = NULL;
	json_t *json_payload = NULL, *json_comp = NULL;
	cjose_err err;

	s_payload = cjose_jwk_to_json(jwk, false, &err);
	if (s_payload == NULL) {
		oauth2_error(log, "cjose_jwk_to_json failed: %s", err.message);
		goto end;
	}

	if (oauth2_json_decode_object(log, s_payload, &json_payload) == false) {
		oauth2_error(log, "decoding JWK JSON failed");
		goto end;
	}

	json_comp = json_object();

	switch (cjose_jwk_get_kty(jwk, &err)) {
	case CJOSE_JWK_KTY_EC:
		json_object_set(json_comp, "crv",
				json_object_get(json_payload, "crv"));
		json_object_set(json_comp, "kty",
				json_object_get(json_payload, "kty"));
		json_object_set(json_comp, "x",
				json_object_get(json_payload, "x"));
		json_object_set(json_comp, "y",
				json_object_get(json_payload, "y"));
		break;
	case CJOSE_JWK_KTY_RSA:
		json_object_set(json_comp, "e",
				json_object_get(json_payload, "e"));
		json_object_set(json_comp, "kty",
				json_object_get(json_payload, "kty"));
		json_object_set(json_comp, "n",
				json_object_get(json_payload, "n"));
		break;
	case CJOSE_JWK_KTY_OCT:
		json_object_set(json_comp, "k",
				json_object_get(json_payload, "k"));
		json_object_set(json_comp, "kty",
				json_object_get(json_payload, "kty"));
		break;
	default:
		oauth2_error(log, "unknown kty");
		goto end;
	}

	s_compact = oauth2_json_encode(log, json_comp,
				       JSON_PRESERVE_ORDER | JSON_COMPACT);

	if (oauth2_jose_hash_bytes(log, OAUTH2_JOSE_OPENSSL_ALG_SHA256,
				   (const unsigned char *)s_compact,
				   strlen(s_compact), hash_bytes,
				   hash_bytes_len) == false) {
		oauth2_error(log, "oauth2_jose_hash_bytes failed");
		goto end;
	}

	rc = true;

end:

	if (s_compact)
		oauth2_mem_free(s_compact);
	if (s_payload)
		cjose_get_dealloc()(s_payload);
	if (json_payload)
		json_decref(json_payload);
	if (json_comp)
		json_decref(json_comp);

	return rc;
}
