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

#include <oauth2/jose.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>

#include "cfg_int.h"
#include "jose_int.h"

#define OAUTH2_HTTP_HDR_DPOP "DPoP"

#define OAUTH_DPOP_HDR_JWK "jwk"
#define OAUTH_DPOP_CLAIM_HTM "htm"
#define OAUTH_DPOP_CLAIM_HTU "htu"
#define OAUTH_DPOP_CLAIM_ATH "ath"
#define OAUTH_DPOP_CLAIM_NONCE "nonce"
#define OAUTH_DPOP_HDR_TYP_VALUE "dpop+jwt"

static bool _oauth2_dpop_jwt_validate(oauth2_log_t *log, const char *s_dpop,
				      cjose_jws_t **jws, cjose_header_t **hdr,
				      json_t **dpop_payload)
{
	bool rc = false;
	cjose_err err;
	uint8_t *plaintext = NULL;
	size_t plaintext_len = 0;
	char *s_payload = NULL;

	*jws = cjose_jws_import(s_dpop, strlen(s_dpop), &err);
	if (*jws == NULL) {
		oauth2_error(log, "cjose_jws_import failed: %s", err.message);
		goto end;
	}

	*hdr = cjose_jws_get_protected(*jws);
	if (*hdr == NULL)
		goto end;

	if (cjose_jws_get_plaintext(*jws, &plaintext, &plaintext_len, &err) ==
	    false) {
		oauth2_error(log, "cjose_jws_get_plaintext failed: %s",
			     err.message);
		goto end;
	}

	s_payload = oauth2_strndup((const char *)plaintext, plaintext_len);

	oauth2_debug(log, "DPOP payload: %s", s_payload);

	if (oauth2_json_decode_object(log, s_payload, dpop_payload) == false) {
		oauth2_error(log, "decoding JWT payload failed");
		goto end;
	}

	rc = true;

end:

	if (s_payload)
		oauth2_mem_free(s_payload);

	return rc;
}

static bool _oauth2_dpop_claims_validate(oauth2_log_t *log, cjose_header_t *hdr,
					 json_t *dpop_payload,
					 cjose_jwk_t **jwk,
					 const char **hdr_typ,
					 const char **hdr_alg, char **clm_htm,
					 char **clm_htu, char **clm_jti,
					 char **clm_ath, char **clm_nonce)
{
	bool rc = false;
	cjose_err err;
	char *hdr_jwk = NULL;
	json_int_t clm_iat = 0;

	*hdr_typ = cjose_header_get(hdr, OAUTH2_JOSE_HDR_TYP, &err);
	if (*hdr_typ == NULL) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP header",
			     OAUTH2_JOSE_HDR_TYP);
		goto end;
	}

	*hdr_alg = cjose_header_get(hdr, CJOSE_HDR_ALG, &err);
	if (*hdr_alg == NULL) {
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

	if ((oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_HTU,
				    clm_htu, NULL) == false) ||
	    (*clm_htu == NULL)) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH_DPOP_CLAIM_HTU);
		goto end;
	}

	if ((oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_HTM,
				    clm_htm, NULL) == false) ||
	    (*clm_htm == NULL)) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH_DPOP_CLAIM_HTM);
		goto end;
	}

	if ((oauth2_json_string_get(log, dpop_payload, OAUTH2_CLAIM_JTI,
				    clm_jti, NULL) == false) ||
	    (*clm_jti == NULL)) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH2_CLAIM_JTI);
		goto end;
	}

	if ((oauth2_json_number_get(log, dpop_payload, OAUTH2_CLAIM_IAT,
				    &clm_iat, 0) == false) ||
	    (clm_iat == 0)) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH2_CLAIM_IAT);
		goto end;
	}

	if ((oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_ATH,
				    clm_ath, NULL) == false) ||
	    (*clm_ath == NULL)) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH_DPOP_CLAIM_ATH);
		goto end;
	}

	if ((oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_NONCE,
				    clm_nonce, NULL) == false) ||
	    (*clm_nonce == NULL)) {
		oauth2_debug(
		    log, "(optional) claim \"%s\" not found in DPOP payload",
		    OAUTH_DPOP_CLAIM_NONCE);
	}

	rc = true;

end:

	if (hdr_jwk)
		cjose_get_dealloc()(hdr_jwk);

	return rc;
}

static bool _oauth2_dpop_hdr_typ_validate(oauth2_log_t *log,
					  const char *hdr_typ)
{
	bool rc = false;

	if (strcasecmp(hdr_typ, OAUTH_DPOP_HDR_TYP_VALUE) != 0) {
		oauth2_error(
		    log,
		    "the %s header value (%s) does not match DPOP value (%s)",
		    OAUTH2_JOSE_HDR_TYP, hdr_typ, OAUTH_DPOP_HDR_TYP_VALUE);
		goto end;
	}

	rc = true;

end:

	return rc;
}

static bool _oauth2_dpop_hdr_alg_validate(oauth2_log_t *log,
					  const char *hdr_alg)
{
	bool rc = false;

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

	rc = true;

end:

	return rc;
}

static bool _oauth2_dpop_sig_verify(oauth2_log_t *log, cjose_jws_t *jws,
				    const cjose_jwk_t *jwk)
{
	bool rc = false;
	cjose_err err;

	if (cjose_jws_verify(jws, jwk, &err) == false) {
		oauth2_error(log, "DPOP signature verification failed: %s",
			     err.message);
		goto end;
	}

	rc = true;

end:

	return rc;
}

static bool _oauth2_dpop_htm_validate(oauth2_log_t *log,
				      oauth2_http_request_t *request,
				      const char *clm_htm)
{
	bool rc = false;
	const char *method = NULL;

	method = oauth2_http_request_method_get_str(log, request);
	if (strcasecmp(method, clm_htm) != 0) {
		oauth2_error(log,
			     "requested HTTP method (%s) does not match DPOP "
			     "\"%s\" value (%s)",
			     method, OAUTH_DPOP_CLAIM_HTM, clm_htm);
		goto end;
	}

	rc = true;

end:

	return rc;
}

static bool _oauth2_dpop_htu_validate(oauth2_log_t *log,
				      oauth2_http_request_t *request,
				      const char *clm_htu)
{
	bool rc = false;
	char *url = NULL;

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

	rc = true;

end:

	if (url)
		oauth2_mem_free(url);

	return rc;
}

static bool _oauth2_dpop_iat_validate(oauth2_log_t *log,
				      oauth2_cfg_dpop_verify_t *verify,
				      json_t *dpop_payload)
{
	bool rc = false;

	if (oauth2_jose_jwt_validate_iat(
		log, dpop_payload, verify->iat_validate,
		verify->iat_slack_before, verify->iat_slack_after) == false)
		goto end;

	rc = true;

end:

	return rc;
}

static bool _oauth2_dpop_jti_validate(oauth2_log_t *log,
				      oauth2_cfg_dpop_verify_t *verify,
				      const char *clm_jti, const char *s_dpop)
{
	bool rc = false;
	char *s_value = NULL;

	oauth2_cache_get(log, verify->cache, clm_jti, &s_value);
	if (s_value != NULL) {
		oauth2_error(log,
			     "a token with the same JTI \"%s\" exists in "
			     "the cache: possible replay attack",
			     clm_jti);
		goto end;
	}

	oauth2_cache_set(log, verify->cache, clm_jti, s_dpop, verify->expiry_s);

	rc = true;

end:

	if (s_value)
		oauth2_mem_free(s_value);

	return rc;
}

static bool(_oauth2_dpp_hdr_count)(oauth2_log_t *log, void *rec,
				   const char *key, const char *value)
{
	int *n = (int *)rec;
	if (strcasecmp(key, OAUTH2_HTTP_HDR_DPOP) == 0)
		(*n)++;
	return true;
}

static bool _oauth2_dpop_header_count(oauth2_log_t *log,
				      oauth2_http_request_t *request)
{
	bool rc = false;
	int n = 0;

	oauth2_http_request_headers_loop(log, request, _oauth2_dpp_hdr_count,
					 &n);

	if (n > 1) {
		oauth2_error(log, "more than one %s header found",
			     OAUTH2_HTTP_HDR_DPOP);
		goto end;
	}

	if (n == 0) {
		oauth2_error(log, "no %s header found", OAUTH2_HTTP_HDR_DPOP);
		goto end;
	}

	rc = true;

end:

	return rc;
}

static bool _oauth2_dpop_ath_validate(oauth2_log_t *log,
				      oauth2_cfg_dpop_verify_t *verify,
				      const char *clm_ath,
				      const char *access_token)
{
	bool rc = false;
	unsigned char *calc = NULL;
	unsigned int calc_len = 0;
	uint8_t *dec = NULL;
	size_t dec_len = 0;

	if ((clm_ath == NULL) || (access_token == NULL))
		goto end;

	if (oauth2_jose_hash_bytes(
		log, "sha256", (const unsigned char *)access_token,
		strlen(access_token), &calc, &calc_len) == false)
		goto end;

	if (oauth2_base64url_decode(log, clm_ath, &dec, &dec_len) == false)
		goto end;

	if ((calc_len != dec_len) || (memcmp(dec, calc, dec_len) != 0)) {
		oauth2_error(log,
			     "provided \"ath\" hash value (%s) does not match "
			     "the calculated value (dec_len=%d, calc_len=%d)",
			     clm_ath, dec_len, calc_len);
		goto end;
	}

	oauth2_debug(log,
		     "successfully validated the provided \"ath\" hash value "
		     "(%s) against the calculated value",
		     clm_ath);

	rc = true;

end:

	if (dec)
		oauth2_mem_free(dec);
	if (calc)
		oauth2_mem_free(calc);

	return rc;
}

static bool _oauth2_dpop_parse_and_validate(oauth2_log_t *log,
					    oauth2_cfg_dpop_verify_t *verify,
					    oauth2_http_request_t *request,
					    const char *access_token,
					    cjose_jwk_t **jwk)
{
	bool rc = false;
	const char *hdr_typ = NULL, *hdr_alg = NULL;
	char *clm_htm = NULL, *clm_htu = NULL, *clm_jti = NULL, *clm_ath = NULL,
	     *clm_nonce = NULL;
	const char *s_dpop = NULL;
	cjose_jws_t *jws = NULL;
	cjose_header_t *hdr = NULL;
	char *s_peek = NULL;
	json_t *dpop_payload = NULL;

	if ((request == NULL) || (verify == NULL) || (jwk == NULL))
		goto end;

	/*
	 * 1.   that there is not more than one DPoP header in the request,
	 */
	if (_oauth2_dpop_header_count(log, request) == false)
		goto end;

	s_dpop =
	    oauth2_http_request_header_get(log, request, OAUTH2_HTTP_HDR_DPOP);
	if (s_dpop == NULL)
		goto end;

	s_peek = oauth2_jose_jwt_header_peek(log, s_dpop, NULL);
	if (s_peek)
		oauth2_debug(log, "DPOP header: %s", s_peek);

	/*
	 * 2.   the string value of the header field is a well-formed JWT,
	 */
	if (_oauth2_dpop_jwt_validate(log, s_dpop, &jws, &hdr, &dpop_payload) ==
	    false)
		goto end;

	/*
	 * 3.   all required claims per Section 4.2 are contained in the JWT,
	 */
	if (_oauth2_dpop_claims_validate(log, hdr, dpop_payload, jwk, &hdr_typ,
					 &hdr_alg, &clm_htm, &clm_htu, &clm_jti,
					 &clm_ath, &clm_nonce) == false)
		goto end;

	/*
	 * 4.   the typ field in the header has the value dpop+jwt,
	 */
	if (_oauth2_dpop_hdr_typ_validate(log, hdr_typ) == false)
		goto end;

	/*
	 * 5.   the algorithm in the header of the JWT indicates an asymmetric
	 *      digital signature algorithm, is not none, is supported by the
	 *      application, and is deemed secure,
	 */
	if (_oauth2_dpop_hdr_alg_validate(log, hdr_alg) == false)
		goto end;

	/*
	 * 6.   the JWT signature verifies with the public key contained in the
	 *      jwk header of the JWT,
	 */
	if (_oauth2_dpop_sig_verify(log, jws, *jwk) == false)
		goto end;

	/*
	 * 7.   the jwk header of the JWT does not contain a private key,
	 */
	// TODO:

	/*
	 * 8.   the htm claim matches the HTTP method value of the HTTP request
	 *      in which the JWT was received,
	 */
	if (_oauth2_dpop_htm_validate(log, request, clm_htm) == false)
		goto end;

	/*
	 * 9.   the htu claim matches the HTTPS URI value for the HTTP request
	 *      in which the JWT was received, ignoring any query and fragment
	 *      parts,
	 */
	if (_oauth2_dpop_htu_validate(log, request, clm_htu) == false)
		goto end;

	/*
	 * 10.  if the server provided a nonce value to the client, the nonce
	 *      claim matches the server-provided nonce value,
	 */
	// TODO:

	/*
	 * 11.  the iat claim value is within an acceptable timeframe and,
	 *      within a reasonable consideration of accuracy and resource
	 *      utilization, a proof JWT with the same jti value has not
	 *      previously been received at the same resource during that time
	 *      period (see Section 11.1),
	 */
	if (_oauth2_dpop_iat_validate(log, verify, dpop_payload) == false)
		goto end;

	if (_oauth2_dpop_jti_validate(log, verify, clm_jti, s_dpop) == false)
		goto end;

	/*
	 * 12.  if presented to a protected resource in conjunction with an
	 *      access token,
	 *
	 *      1.  ensure that the value of the ath claim equals the hash of
	 *          that access token,
	 */
	if (_oauth2_dpop_ath_validate(log, verify, clm_ath, access_token) ==
	    false)
		goto end;

	/*
	 *      2.  confirm that the public key to which the access token is
	 *          bound matches the public key from the DPoP proof.
	 *
	 */
	// done in the calling function oauth2_dpop_token_verify with the "jkt"
	// claim

	rc = true;

end:

	if (s_peek)
		oauth2_mem_free(s_peek);
	if (clm_htu)
		oauth2_mem_free(clm_htu);
	if (clm_htm)
		oauth2_mem_free(clm_htm);
	if (clm_jti)
		oauth2_mem_free(clm_jti);
	if (clm_ath)
		oauth2_mem_free(clm_ath);
	if (clm_nonce)
		oauth2_mem_free(clm_nonce);
	if (dpop_payload)
		json_decref(dpop_payload);
	if (jws)
		cjose_jws_release(jws);

	return rc;
}

#define OAUTH_DPOP_CLAIM_CNF "cnf"
#define OAUTH_DPOP_CLAIM_CNF_JKT "jkt"

bool oauth2_dpop_token_verify(oauth2_log_t *log,
			      oauth2_cfg_dpop_verify_t *verify,
			      oauth2_http_request_t *request,
			      const char *access_token, json_t *json_payload)
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

	if (_oauth2_dpop_parse_and_validate(log, verify, request, access_token,
					    &jwk) == false)
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
			     "match \"%s\" claim \%s\" for the access token",
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
