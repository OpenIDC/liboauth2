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

#include <oauth2/jose.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>

#include "cfg_int.h"
#include "jose_int.h"

#define OAUTH2_HTTP_HDR_DPOP "DPoP"

#define OAUTH_DPOP_HDR_JWK "jwk"
#define OAUTH_DPOP_CLAIM_HTM "htm"
#define OAUTH_DPOP_CLAIM_HTU "htu"
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
					 char **clm_htu, char **clm_jti)
{
	bool rc = false;
	cjose_err err;
	char *hdr_jwk = NULL;
	json_int_t clm_iat;

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

	if (oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_HTU,
				   clm_htu, NULL) == false) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH_DPOP_CLAIM_HTU);
		goto end;
	}

	if (oauth2_json_string_get(log, dpop_payload, OAUTH_DPOP_CLAIM_HTM,
				   clm_htm, NULL) == false) {
		oauth2_error(log,
			     "required claim \"%s\" not found in DPOP payload",
			     OAUTH_DPOP_CLAIM_HTM);
		goto end;
	}

	if (oauth2_json_string_get(log, dpop_payload, OAUTH2_CLAIM_JTI, clm_jti,
				   NULL) == false) {
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

static bool _oauth2_dpop_parse_and_validate(oauth2_log_t *log,
					    oauth2_cfg_dpop_verify_t *verify,
					    oauth2_http_request_t *request,
					    cjose_jwk_t **jwk)
{
	bool rc = false;
	const char *hdr_typ = NULL, *hdr_alg = NULL;
	char *clm_htm = NULL, *clm_htu = NULL, *clm_jti = NULL;
	const char *s_dpop = NULL;
	cjose_jws_t *jws = NULL;
	cjose_header_t *hdr = NULL;
	char *s_peek = NULL;
	json_t *dpop_payload = NULL;

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
	 * 1. the string value is a well-formed JWT
	 */
	if (_oauth2_dpop_jwt_validate(log, s_dpop, &jws, &hdr, &dpop_payload) ==
	    false)
		goto end;

	/*
	 * 2.  all required claims are contained in the JWT,
	 */
	if (_oauth2_dpop_claims_validate(log, hdr, dpop_payload, jwk, &hdr_typ,
					 &hdr_alg, &clm_htm, &clm_htu,
					 &clm_jti) == false)
		goto end;

	/*
	 * 3.  the "typ" field in the header has the value "dpop+jwt",
	 */
	if (_oauth2_dpop_hdr_typ_validate(log, hdr_typ) == false)
		goto end;

	/*
	 * 4.  the algorithm in the header of the JWT indicates an asymmetric
	 *    digital signature algorithm, is not "none", is supported by the
	 *   application, and is deemed secure,
	 */
	if (_oauth2_dpop_hdr_alg_validate(log, hdr_alg) == false)
		goto end;

	/*
	 * 5.  that the JWT is signed using the public key contained in the
	 *   "jwk" header of the JWT,
	 */
	if (_oauth2_dpop_sig_verify(log, jws, *jwk) == false)
		goto end;

	/*
	 * 6.  the "htm" claim matches the HTTP method value of the HTTP request
	 *  in which the JWT was received (case-insensitive),
	 */
	if (_oauth2_dpop_htm_validate(log, request, clm_htm) == false)
		goto end;

	/*
	 * 7.  the "htu" claims matches the HTTP URI value for the HTTP request
	 *    in which the JWT was received, ignoring any query and fragment
	 *    parts,
	 */
	if (_oauth2_dpop_htu_validate(log, request, clm_htu) == false)
		goto end;

	/*
	 * 8.  the token was issued within an acceptable timeframe (see
	 *     Section 9.1), and
	 */
	if (_oauth2_dpop_iat_validate(log, verify, dpop_payload) == false)
		goto end;

	/*
	 * 9.  that, within a reasonable consideration of accuracy and resource
	 *     utilization, a JWT with the same "jti" value has not been
	 *     received previously (see Section 9.1).
	 */
	if (_oauth2_dpop_jti_validate(log, verify, s_dpop, clm_jti) == false)
		goto end;

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

	if (_oauth2_dpop_parse_and_validate(log, verify, request, &jwk) ==
	    false)
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
