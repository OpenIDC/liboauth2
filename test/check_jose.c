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

#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"
#include <check.h>
#include <stdlib.h>

#include "check_liboauth2.h"
#include "jose_int.h"

static oauth2_log_t *log = 0;

static const char *secret1 = NULL;
static const char *secret2 = NULL;

static json_t *payload1 = NULL;
const char *s_payload1 = NULL;

static json_t *payload2 = NULL;
const char *s_payload2 = NULL;

static const char *serialized_hdr = NULL;
static const char *encrypted1 = NULL;
static const char *encrypted1_corrupt_tag = NULL;

static const char *encrypted1_signed2 = NULL;
static const char *encrypted1_signed2_corrupt_sig = NULL;
static const char *encrypted1_signed2_corrupt_hdr = NULL;
static const char *encrypted1_signed2_corrupt_payload = NULL;

static void setup(void)
{
	log = oauth2_init(OAUTH2_LOG_TRACE1, 0);

	secret1 = "12345";
	secret2 = "abcde";

	s_payload1 = "{\"iss\":\"https://example.org\"}";
	json_error_t err;
	payload1 = json_loads(s_payload1, 0, &err);

	s_payload2 = "{\"aud\":\"https://another.org\"}";
	payload2 = json_loads(s_payload2, 0, &err);

	serialized_hdr = "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..";
	encrypted1 =
	    "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..-"
	    "jvbGVBwu8GOvVwF.3lPSed2UdIu-"
	    "obtRNcMaCP7WUYETLwkXD2BZbx0sjOUiRNbHXQmYm7c0B4Mp2f2m-C-"
	    "hAzBdlPGDjeNP1PiFZiWFtDRGuskW4qGrUoFCSWZx5vAyfOFjuRN2ydst7"
	    "geoD32_8zY-pYyVzQ.HWN2Hq8sLnFWT_XKU20Mpw";

	// encrypted_wrong_payload =

	encrypted1_corrupt_tag =
	    "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..-"
	    "jvbGVBwu8GOvVwF.3lPSed2UdIu-"
	    "obtRNcMaCP7WUYETLwkXD2BZbx0sjOUiRNbHXQmYm7c0B4Mp2f2m-C-"
	    "hAzBdlPGDjeNP1PiFZiWFtDRGuskW4qGrUoFCSWZx5vAyfOFjuRN2ydst7"
	    "geoD32_8zY-pYyVzQ.HWN2Hq8sLnFWT_XKU20MpW";

	encrypted1_signed2 = "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0.."
			     "4lW9e06wrl3DMuNs.-"
			     "wmcLlYUPuGGWKPIimR3j66Y15yarBpaF75g07Q23epRmYO7NL"
			     "Gvwt7tiGYJGxqh_6f9SHJDK7wMYR4GsP6W4AZWZOurCxY_"
			     "PdwZWnrPit11s7zi77fFEqz3b3g2scYbZd9PfN-KJ4Ol0g."
			     "oH5VdKxGZanSP0H0-XuGtg";

	encrypted1_signed2_corrupt_sig =
	    "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..f-t6lZhrSTUwQUhe."
	    "1fIV8PJSgpoOgiR-0yVlkzzcgfpEghVnevJuYbO06DA9x-"
	    "X47wzpoIPIX941fXmSFIItQDiF1t9lVxfIhnJ46JYuYlOCwkn_"
	    "6vUIQKpCbGbUNwvrPo8aF8g75T8FMKmeqjjawmby2nwawQ."
	    "Sm6gRVXw7RhI7NI2hfIglg";

	encrypted1_signed2_corrupt_hdr =
	    "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..0yJnmp9r_YW8am-4."
	    "Qe6GoANyIV3ET_bb4Npr-QguqGzzTNrm_"
	    "iWvx5iYchUr8HL1Qv8jWQq8FOeuNHhbdNW0huKhH_rjfNA_"
	    "bNHN6nUGmHmeSkhWMKPsf2JnrDZIdcCN7uXVxhKeMXe5TGZ6sY5AdF7lX8Ufcg."
	    "auXeS-tKPnxFj-iUYULfOQ";

	encrypted1_signed2_corrupt_payload =
	    "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..eeCTIS3jEdKO45ao.PM_"
	    "PHuxN-zPZ9gNVLgpuXZl5dXCTCTQedYCj_"
	    "QBoOrKhg93A1QOrj1NcHt0NSspDkJ9PpVnJG6T1nzKPIZsdWHHjse33xqs4HNbDW2y"
	    "bBMuZFQ_S9eEDfEVusEcls0cg0pcrtemeJ8fb.NDWKfDRNgbl5anMH1NCbIw";
}

static void teardown(void)
{
	json_decref(payload1);
	json_decref(payload2);
	oauth2_shutdown(log);
}

static void *faulty_alloc(size_t amt)
{
	return NULL;
}

START_TEST(test_hash_bytes)
{
	bool rc;
	const char *src = "abc";
	unsigned char src_hash[32] = {
	    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
	    0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
	    0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

	unsigned int dst_len;
	unsigned char *dst;
	oauth2_mem_alloc_fn_t alloc_save;

	dst = NULL;
	dst_len = 0;
	rc = oauth2_jose_hash_bytes(log, OAUTH2_JOSE_OPENSSL_ALG_SHA256,
				    (const unsigned char *)src, strlen(src),
				    &dst, &dst_len);
	ck_assert_int_eq(rc, true);
	ck_assert_int_eq(sizeof(src_hash), dst_len);
	oauth2_mem_free(dst);

	dst = NULL;
	dst_len = 0;
	alloc_save = oauth2_mem_get_alloc();
	oauth2_mem_set_alloc_funcs(faulty_alloc, oauth2_mem_get_realloc(),
				   oauth2_mem_get_dealloc());

	rc = oauth2_jose_hash_bytes(log, OAUTH2_JOSE_OPENSSL_ALG_SHA256,
				    (const unsigned char *)src, strlen(src),
				    &dst, &dst_len);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(dst, NULL);
	ck_assert_int_eq(dst_len, 0);

	dst = (unsigned char *)oauth2_strdup("test-faulty-alloc");
	ck_assert_ptr_eq(dst, NULL);
	oauth2_mem_set_alloc_funcs(alloc_save, oauth2_mem_get_realloc(),
				   oauth2_mem_get_dealloc());

	dst = NULL;
	dst_len = 0;
	rc = oauth2_jose_hash_bytes(log, "non-existing-digest",
				    (const unsigned char *)src, strlen(src),
				    &dst, &dst_len);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(dst, NULL);
	ck_assert_int_eq(dst_len, 0);

	rc = oauth2_jose_hash_bytes(log, OAUTH2_JOSE_OPENSSL_ALG_SHA256, NULL,
				    0, &dst, &dst_len);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(dst, NULL);
	ck_assert_int_eq(dst_len, 0);

	rc = oauth2_jose_hash_bytes(log, OAUTH2_JOSE_OPENSSL_ALG_SHA256, NULL,
				    0, NULL, NULL);
	ck_assert_int_eq(rc, false);
}
END_TEST

START_TEST(test_jwk_create_symmetric)
{
	bool rc;
	const char *client_secret = "abc";
	oauth2_jose_jwk_t *jwk = NULL;

	rc = oauth2_jose_jwk_create_symmetric(log, client_secret, NULL, &jwk);
	ck_assert_int_eq(rc, true);
	oauth2_jose_jwk_release(jwk);

	rc = oauth2_jose_jwk_create_symmetric(
	    log, client_secret, OAUTH2_JOSE_OPENSSL_ALG_SHA256, &jwk);
	ck_assert_int_eq(rc, true);
	oauth2_jose_jwk_release(jwk);

	jwk = NULL;
	rc = oauth2_jose_jwk_create_symmetric(
	    log, NULL, OAUTH2_JOSE_OPENSSL_ALG_SHA256, &jwk);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(jwk, NULL);

	rc = oauth2_jose_jwk_create_symmetric(log, NULL, NULL, &jwk);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(jwk, NULL);

	rc = oauth2_jose_jwk_create_symmetric(log, client_secret,
					      "bogus-algorithm", &jwk);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(jwk, NULL);
}
END_TEST

START_TEST(test_jwt_encrypt)
{
	bool rc;
	char *cser = NULL;

	rc = oauth2_jose_jwt_encrypt(log, secret1, payload1, &cser);

	ck_assert_int_eq(rc, true);
	// TODO: this fails intermittently in docker-valgrind (only on first
	// runs...) !?
	ck_assert(strncmp(cser, serialized_hdr, strlen(serialized_hdr)) == 0);

	oauth2_mem_free(cser);
	cser = NULL;

	rc = oauth2_jose_jwt_encrypt(log, secret2, payload2, &cser);
	ck_assert_int_eq(rc, true);
	ck_assert(strncmp(cser, serialized_hdr, strlen(serialized_hdr)) == 0);

	oauth2_mem_free(cser);
	cser = NULL;

	rc = oauth2_jose_jwt_encrypt(log, NULL, payload1, &cser);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(cser, NULL);

	rc = oauth2_jose_jwt_encrypt(log, secret1, NULL, &cser);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(cser, NULL);

	rc = oauth2_jose_jwt_encrypt(log, secret1, payload1, NULL);
	ck_assert_int_eq(rc, false);
}
END_TEST

START_TEST(test_jwt_decrypt)
{
	bool rc;
	char *cser = NULL;
	json_t *result = NULL;

	rc = oauth2_jose_jwt_decrypt(log, secret1, encrypted1, &result);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(result, NULL);

	cser = json_dumps(payload1, JSON_PRESERVE_ORDER | JSON_COMPACT);
	ck_assert_str_eq(cser, s_payload1);

	oauth2_mem_free(cser);
	json_decref(result);

	result = NULL;
	rc = oauth2_jose_jwt_decrypt(log, secret1, encrypted1_corrupt_tag,
				     &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(log, secret1, encrypted1_signed2, &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(log, secret1,
				     encrypted1_signed2_corrupt_sig, &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(log, secret1,
				     encrypted1_signed2_corrupt_hdr, &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(
	    log, secret1, encrypted1_signed2_corrupt_payload, &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(log, secret2, encrypted1, &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(log, NULL, encrypted1, &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(log, secret1, NULL, &result);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(result, NULL);

	rc = oauth2_jose_jwt_decrypt(log, secret1, encrypted1, NULL);
	ck_assert_int_eq(rc, false);
}
END_TEST

static char *get_jwks_uri_json =
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"use\":\"sig\",\"n\":"
    "\"hKvkosOyK33gznaRCNgakMLE2GHS5_7K34oqZRsAWC-7aC420eJNL2z_"
    "8Z7ouWXpJNZ2YHQcqxPe4UZGtiDiFYLdDbQPrCDiTpuRYybe1UmZJ3Kk5fBx9yXKU0zbdSKYPE"
    "eq1w5Fi7rt46YkZ6qwv3Yixo7eTxbglezJOx_YcS5sfXxcwBU1nYbGU_"
    "MgrBXAfy1Hea5tcUSPot-BTMcuj_doHLT_sEm4AZwaZiLhMiqfI-"
    "J6Gv5Hg6aBTXpYv50DEdcoZzkabMHxjHICS9w2FGWAzMt_"
    "AvW4ISlbAxlBroXhTEXC6GIJwoDTskuPlCO4CVa3axh0s1D49JFJoBYasw\",\"e\":"
    "\"AQAB\",\"x5c\":["
    "\"MIIDSjCCAjKgAwIBAgIGAVvvqweOMA0GCSqGSIb3DQEBCwUAMGYxCzAJBgNVBAYTAlVTMQsw"
    "CQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ0wCwYDVQQKEwRQaW5nMQwwCgYDVQQLEwNEZX"
    "YxHDAaBgNVBAMTE0NvbmZpZyBTaWduaW5nIENlcnQwHhcNMTcwNTEwMDAwMzM0WhcNMzIwNTA2"
    "MDAwMzM0WjBmMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjENMA"
    "sGA1UEChMEUGluZzEMMAoGA1UECxMDRGV2MRwwGgYDVQQDExNDb25maWcgU2lnbmluZyBDZXJ0"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhKvkosOyK33gznaRCNgakMLE2GHS5/"
    "7K34oqZRsAWC+7aC420eJNL2z/"
    "8Z7ouWXpJNZ2YHQcqxPe4UZGtiDiFYLdDbQPrCDiTpuRYybe1UmZJ3Kk5fBx9yXKU0zbdSKYPE"
    "eq1w5Fi7rt46YkZ6qwv3Yixo7eTxbglezJOx/YcS5sfXxcwBU1nYbGU/"
    "MgrBXAfy1Hea5tcUSPot+BTMcuj/doHLT/"
    "sEm4AZwaZiLhMiqfI+J6Gv5Hg6aBTXpYv50DEdcoZzkabMHxjHICS9w2FGWAzMt/"
    "AvW4ISlbAxlBroXhTEXC6GIJwoDTskuPlCO4CVa3axh0s1D49JFJoBYaswIDAQABMA0GCSqGSI"
    "b3DQEBCwUAA4IBAQBCYXguSAbrwHw9g+UXuWzgj6b3jN+"
    "OAAQUuvpnY0KrNBentCgC3ualfgieB2c0cyLXBFTNDzMCVb2eB+f66/"
    "ZRQC8W6DTc5aCE3nTH8tSzbMLwwlMnQelkQMF4LZ9NZmrubVT2IYZ+"
    "hzwHhvVOHSQ6kqjQHXWcZ30VEbe6EV47LC1M78v+UX3CP+"
    "lOcovbyHl9J4VqQLKlxajr0QAqHnETkr84fI54RE2kSkWVuWp36VNY39Sl0/"
    "yEmnouFbV0UBMZck7gMNseCtwSYdkwls/LDFEp9D4rF1gHRlSBRskNc/"
    "NaasTSX4JpNf+xakm7yePtuWyAY/"
    "fQ7ETSPMJdVEaL\"],\"x5t\":\"31YdH_bv2Hlg89wmwBphxJZaK64\"}]}";
static char *jwks_uri_path = "/jwks_uri";

static char *oauth2_check_jose_serve_get(const char *request)
{
	if (strncmp(request, jwks_uri_path, strlen(jwks_uri_path)) == 0) {
		return oauth2_strdup(get_jwks_uri_json);
	}
	return oauth2_strdup("problem");
}

OAUTH2_CHECK_HTTP_PATHS

START_TEST(test_jwks_resolve_uri)
{
	oauth2_cfg_token_verify_t *verify = NULL;
	oauth2_jose_jwk_list_t *list = NULL;
	const char *rv = NULL;
	bool refresh = false;
	char *url = NULL;
	oauth2_jose_jwt_verify_ctx_t *ptr = NULL;

	url = oauth2_stradd(NULL, oauth2_check_http_base_url(), jwks_uri_path,
			    NULL);
	rv = oauth2_cfg_token_verify_add_options(log, &verify, "jwks_uri", url,
						 "ssl_verify=false");
	ck_assert_ptr_eq(rv, NULL);

	ptr = (oauth2_jose_jwt_verify_ctx_t *)verify->ctx->ptr;
	list = ptr->jwks_provider->resolve(log, ptr->jwks_provider, &refresh);
	ck_assert_ptr_ne(list, NULL);

	oauth2_jose_jwk_list_free(log, list);
	oauth2_mem_free(url);
	oauth2_cfg_token_verify_free(log, verify);
}
END_TEST

START_TEST(test_jwk_resolve_plain)
{
	oauth2_cfg_token_verify_t *verify = NULL;
	oauth2_jose_jwk_list_t *list = NULL;
	const char *rv = NULL;
	bool refresh = false;
	oauth2_jose_jwt_verify_ctx_t *ptr = NULL;

	rv = oauth2_cfg_token_verify_add_options(log, &verify, "plain",
						 "mysecret", "kid=mykid");
	ck_assert_ptr_eq(rv, NULL);

	ptr = (oauth2_jose_jwt_verify_ctx_t *)verify->ctx->ptr;
	list = ptr->jwks_provider->resolve(log, ptr->jwks_provider, &refresh);
	ck_assert_ptr_ne(list, NULL);

	oauth2_jose_jwk_list_free(log, list);
	oauth2_cfg_token_verify_free(log, verify);
}
END_TEST

Suite *oauth2_check_jose_suite()
{
	Suite *s = suite_create("jose");
	TCase *c = tcase_create("core");

	liboauth2_check_register_http_callbacks(
	    oauth2_check_http_base_path(), oauth2_check_jose_serve_get, NULL);

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_hash_bytes);
	tcase_add_test(c, test_jwk_create_symmetric);
	tcase_add_test(c, test_jwt_encrypt);
	tcase_add_test(c, test_jwt_decrypt);
	tcase_add_test(c, test_jwks_resolve_uri);
	tcase_add_test(c, test_jwk_resolve_plain);

	suite_add_tcase(s, c);

	return s;
}
