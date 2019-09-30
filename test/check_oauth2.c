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

#include "check_liboauth2.h"
#include "oauth2/mem.h"
#include "oauth2/oauth2.h"
#include "oauth2_int.h"
#include <check.h>
#include <stdlib.h>

static oauth2_log_t *log = 0;

static void setup(void)
{
	log = oauth2_log_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_log_free(log);
}

START_TEST(test_oauth2_verify_clone)
{
	oauth2_cfg_token_verify_t *src = NULL, *dst = NULL;
	char *rv = NULL;

	rv = oauth2_cfg_token_verify_add_options(log, &src, "plain", "mysecret",
						 NULL);
	ck_assert_ptr_eq(rv, NULL);

	dst = oauth2_cfg_token_verify_clone(log, src);

	rv = oauth2_cfg_cache_set_options(log, NULL, NULL, NULL, 0);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	oauth2_cfg_token_verify_free(log, dst);
	oauth2_cfg_token_verify_free(log, src);
}
END_TEST

static void test_oauth_auth_clone(oauth2_cfg_endpoint_auth_t *src)
{
	bool rc = false;
	oauth2_cfg_endpoint_auth_t *dst = NULL;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_nv_list_t *params = NULL;

	params = oauth2_nv_list_init(log);
	ctx = oauth2_http_call_ctx_init(log);

	dst = oauth2_cfg_endpoint_auth_clone(log, src);
	ck_assert_ptr_ne(dst, NULL);
	rc = oauth2_http_ctx_auth_add(log, ctx, dst, params);
	ck_assert_int_eq(rc, true);

	oauth2_nv_list_free(log, params);
	oauth2_cfg_endpoint_auth_free(log, dst);
	oauth2_http_call_ctx_free(log, ctx);
}

START_TEST(test_oauth2_auth_client_secret_basic)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	oauth2_nv_list_t *params = NULL;
	char *rv = NULL;
	//	const char *str = NULL;

	// TODO: make the actual call
	ctx = oauth2_http_call_ctx_init(log);
	params = oauth2_nv_list_init(log);

	auth = oauth2_cfg_endpoint_auth_init(log);
	rv = oauth2_cfg_endpoint_auth_add_options(
	    log, auth, "client_secret_basic", params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "client_id", "myclient");
	rv = oauth2_cfg_endpoint_auth_add_options(
	    log, auth, "client_secret_basic", params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "client_secret", "mysecret");
	rv = oauth2_cfg_endpoint_auth_add_options(
	    log, auth, "client_secret_basic", params);
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_int_eq(OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_BASIC,
			 oauth2_cfg_endpoint_auth_type(auth));

	rc = oauth2_http_ctx_auth_add(log, ctx, auth, NULL);
	ck_assert_int_eq(rc, true);

	test_oauth_auth_clone(auth);

	//	str = oauth2_http_call_ctx_hdr_get(log, ctx, "Authorization");
	//	ck_assert_ptr_ne(str, NULL);
	//	ck_assert_str_eq(str, "bXljbGllbnQ6bXlzZWNyZXQ=");

	oauth2_cfg_endpoint_auth_free(log, auth);
	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

START_TEST(test_oauth2_auth_client_secret_post)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	oauth2_nv_list_t *params = NULL;
	oauth2_nv_list_t *post = NULL;
	char *rv = NULL;
	const char *str = NULL;

	ctx = oauth2_http_call_ctx_init(log);
	params = oauth2_nv_list_init(log);

	auth = oauth2_cfg_endpoint_auth_init(log);
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth,
						  "client_secret_post", params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "client_id", "myclient");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth,
						  "client_secret_post", params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "client_secret", "mysecret");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth,
						  "client_secret_post", params);
	ck_assert_ptr_eq(rv, NULL);

	post = oauth2_nv_list_init(log);
	rc = oauth2_http_ctx_auth_add(log, ctx, auth, post);
	ck_assert_int_eq(rc, true);
	ck_assert_int_eq(OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_POST,
			 oauth2_cfg_endpoint_auth_type(auth));

	str = oauth2_nv_list_get(log, post, "client_id");
	ck_assert_ptr_ne(str, NULL);
	ck_assert_str_eq(str, "myclient");
	str = oauth2_nv_list_get(log, post, "client_secret");
	ck_assert_ptr_ne(str, NULL);
	ck_assert_str_eq(str, "mysecret");
	oauth2_nv_list_free(log, post);

	test_oauth_auth_clone(auth);

	oauth2_cfg_endpoint_auth_free(log, auth);
	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

START_TEST(test_oauth2_auth_client_secret_jwt)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	oauth2_nv_list_t *params = NULL;
	oauth2_nv_list_t *post = NULL;
	char *rv = NULL;
	const char *str = NULL;

	ctx = oauth2_http_call_ctx_init(log);
	params = oauth2_nv_list_init(log);

	auth = oauth2_cfg_endpoint_auth_init(log);
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth,
						  "client_secret_jwt", params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "client_id", "myclient");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth,
						  "client_secret_jwt", params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "client_secret", "mysecret");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth,
						  "client_secret_jwt", params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "aud", "myaud");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth,
						  "client_secret_jwt", params);
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_int_eq(OAUTH2_ENDPOINT_AUTH_CLIENT_SECRET_JWT,
			 oauth2_cfg_endpoint_auth_type(auth));

	post = oauth2_nv_list_init(log);
	rc = oauth2_http_ctx_auth_add(log, ctx, auth, post);
	ck_assert_int_eq(rc, true);
	str = oauth2_nv_list_get(log, post, "client_assertion_type");
	ck_assert_ptr_ne(str, NULL);
	ck_assert_str_eq(
	    str, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
	str = oauth2_nv_list_get(log, post, "client_assertion");
	ck_assert_ptr_ne(str, NULL);
	ck_assert(
	    strncmp(str, "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.",
		    strlen("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.")) == 0);
	oauth2_nv_list_free(log, post);

	test_oauth_auth_clone(auth);

	oauth2_cfg_endpoint_auth_free(log, auth);
	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

START_TEST(test_oauth2_auth_private_key_jwt)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	oauth2_nv_list_t *params = NULL;
	oauth2_nv_list_t *post = NULL;
	char *rv = NULL;
	const char *str = NULL;
	const char *s_jwk = NULL;

	s_jwk =
	    "{"
	    "\"kty\" : \"RSA\","
	    "\"n\": "
	    "\"ym7jipmB37CgdonwGFVRuZmRfCl3lVh91fmm5CXHcNlUFZNR3D6Q9r63PpGRnfSs"
	    "X3dOweh8BXd2AJ3mxvcE4z9xH--tA5EaOGI7IVF0Ip_"
	    "i3flGg85xOADlb8rX3ez1NqkqMVJeeJypKhCCDNfvu_"
	    "MXSdPLglU969YQF5xKAK8VFRfI6EfxxrZ_3Dvt2CKDV4LTPPJe9KI2_"
	    "LuLQFBJ3MzlCTVxY6gyaljrWaDq7q5Lt3GB1KYS0Yd8COEQwsclOLm0Tddhg4cle-"
	    "DfaTMi7xsTZsPKyac5x17Y4N4isHhZULuWHX7o1bs809xcj-_-YCRq6C61je_"
	    "mzFhuF4pczw\","
	    "\"e\": \"AQAB\","
	    "\"d\": "
	    "\"qvxW_"
	    "e8DoCnUn8uLHUKTsS1hkXqFI4SHZYFl0jeG6m7ncwHolxvR3ljg9tyGHuFX55sizu7"
	    "MMuHgrkyxbUWgv0ILD2qmvOiHOTDfuRjP-58JRW0UfqiVQTSgl3jCNRW9WdoxZU-"
	    "ptD6_NGSVNLwAJsUB2r4mm4PctaMuHINKjp_TnuD-5vfi9Tj88hbqvX_"
	    "0j8T62ZaLRdERb1KGDM_"
	    "8bnqQpnLZ0MZQnpLQ8cKIcjj7p0II6pzvqgdO1RqfYx7qG0cbcIRh26rnB9X4rp5Br"
	    "bvDzKe6NOqacZUcNUmbPzI01-hiT0HgJvV592CBOxt2T31ltQ4wCEdzhQeT3n9_"
	    "wQ\""
	    "}";

	ctx = oauth2_http_call_ctx_init(log);
	params = oauth2_nv_list_init(log);

	auth = oauth2_cfg_endpoint_auth_init(log);
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "private_key_jwt",
						  params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "client_id", "myclient");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "private_key_jwt",
						  params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "jwk", s_jwk);
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "private_key_jwt",
						  params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	ck_assert_ptr_ne(auth, NULL);
	oauth2_nv_list_add(log, params, "aud", "myaud");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "private_key_jwt",
						  params);
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_int_eq(OAUTH2_ENDPOINT_AUTH_PRIVATE_KEY_JWT,
			 oauth2_cfg_endpoint_auth_type(auth));

	post = oauth2_nv_list_init(log);
	rc = oauth2_http_ctx_auth_add(log, ctx, auth, post);
	ck_assert_int_eq(rc, true);
	str = oauth2_nv_list_get(log, post, "client_assertion_type");
	ck_assert_ptr_ne(str, NULL);
	ck_assert_str_eq(
	    str, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
	str = oauth2_nv_list_get(log, post, "client_assertion");
	ck_assert_ptr_ne(str, NULL);
	ck_assert(
	    strncmp(str, "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.",
		    strlen("eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.")) == 0);
	oauth2_nv_list_free(log, post);

	test_oauth_auth_clone(auth);

	oauth2_cfg_endpoint_auth_free(log, auth);
	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

START_TEST(test_oauth2_auth_client_cert)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	oauth2_nv_list_t *params = NULL;
	char *rv = NULL;

	// TODO: make the actual call
	ctx = oauth2_http_call_ctx_init(log);
	params = oauth2_nv_list_init(log);

	auth = oauth2_cfg_endpoint_auth_init(log);
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "client_cert",
						  params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "cert", "mycert.pem");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "client_cert",
						  params);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);
	oauth2_cfg_endpoint_auth_free(log, auth);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "key", "mykey.pem");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "client_cert",
						  params);
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_int_eq(OAUTH2_ENDPOINT_AUTH_CLIENT_CERT,
			 oauth2_cfg_endpoint_auth_type(auth));
	rc = oauth2_http_ctx_auth_add(log, ctx, auth, NULL);
	ck_assert_int_eq(rc, true);

	test_oauth_auth_clone(auth);

	oauth2_cfg_endpoint_auth_free(log, auth);
	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

START_TEST(test_oauth2_auth_http_basic)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	oauth2_nv_list_t *params = NULL;
	char *rv = NULL;

	// TODO: make the actual call
	ctx = oauth2_http_call_ctx_init(log);
	params = oauth2_nv_list_init(log);

	auth = oauth2_cfg_endpoint_auth_init(log);
	oauth2_nv_list_add(log, params, "username", "myuser");
	oauth2_nv_list_add(log, params, "password", "mysecret");
	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "basic", params);
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_int_eq(OAUTH2_ENDPOINT_AUTH_BASIC,
			 oauth2_cfg_endpoint_auth_type(auth));
	rc = oauth2_http_ctx_auth_add(log, ctx, auth, NULL);
	ck_assert_int_eq(rc, true);

	test_oauth_auth_clone(auth);

	oauth2_cfg_endpoint_auth_free(log, auth);
	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

START_TEST(test_oauth2_auth_none)
{
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;
	oauth2_nv_list_t *params = NULL;
	char *rv = NULL;

	rv = oauth2_cfg_endpoint_auth_add_options(log, NULL, "none", NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	ctx = oauth2_http_call_ctx_init(log);
	auth = oauth2_cfg_endpoint_auth_init(log);
	ck_assert_ptr_ne(auth, NULL);

	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "bogus", NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	rv = oauth2_cfg_endpoint_auth_add_options(log, auth, "none", NULL);
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_int_eq(OAUTH2_ENDPOINT_AUTH_NONE,
			 oauth2_cfg_endpoint_auth_type(auth));

	rc = oauth2_http_ctx_auth_add(log, ctx, auth, NULL);
	ck_assert_int_eq(rc, true);

	test_oauth_auth_clone(auth);

	oauth2_cfg_endpoint_auth_free(log, auth);
	oauth2_nv_list_free(log, params);
	oauth2_http_call_ctx_free(log, ctx);
}
END_TEST

OAUTH2_CHECK_HTTP_PATHS

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
static char *get_jwks_uri_path = "/jwks_uri";

static char *get_eckey_pem =
    "-----BEGIN PUBLIC "
    "KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXJ+33eo/"
    "U6z4PGV0++"
    "Qdj1Ev2363\n47i7PxTx8Tr87RYHXIIXLRmH1aIz0OVLt4eM9iXDlDGB6ldBFsM8P61nqQ=="
    "\n-----END PUBLIC KEY-----";
static char *get_eckey_url_path = "/ec_key";

static char *introspection_result_json = "{ \"active\": true }";

static char *post_introspection_path = "/introspection";
const char *valid_access_token = "my_valid_token";

static char *metadata_path = "/.well-known/oauth2-configuration";

static char metadata[512];

static char *get_metadata_json()
{
	static char *format = "{"
			      "\"jwks_uri\": \"%s%s\","
			      "\"introspection_endpoint\": \"%s%s\""
			      "}";
	oauth2_snprintf(metadata, sizeof(metadata), format,
			oauth2_check_http_base_url(), get_jwks_uri_path,
			oauth2_check_http_base_url(), post_introspection_path);
	return metadata;
}

static char *oauth2_check_oauth2_serve_get(const char *request)
{
	char *rv = NULL;

	if (strncmp(request, get_jwks_uri_path, strlen(get_jwks_uri_path)) ==
	    0) {
		rv = oauth2_strdup(get_jwks_uri_json);
		goto end;
	}
	if (strncmp(request, get_eckey_url_path, strlen(get_eckey_url_path)) ==
	    0) {
		rv = oauth2_strdup(get_eckey_pem);
		goto end;
	}
	if (strncmp(request, metadata_path, strlen(metadata_path)) == 0) {
		rv = oauth2_strdup(get_metadata_json());
		goto end;
	}

	rv = oauth2_strdup("problem");

end:

	return rv;
}

static char *oauth2_check_oauth2_serve_post(const char *request)
{
	oauth2_nv_list_t *params = NULL;
	char *data = NULL;
	const char *token = NULL;
	const char *sep = "****";
	char *rv = NULL;

	if (strncmp(request, post_introspection_path,
		    strlen(post_introspection_path)) == 0) {
		request += strlen(post_introspection_path) + 5;
		data = strstr(request, sep);
		if (data == NULL)
			goto error;
		data += strlen(sep);
		if (oauth2_parse_form_encoded_params(log, data, &params) ==
		    false)
			goto error;
		token = oauth2_nv_list_get(log, params, "token");
		if (token == NULL)
			goto error;
		if ((token) && (strcmp(token, valid_access_token) == 0))
			rv = oauth2_strdup(introspection_result_json);
		else
			rv = oauth2_strdup("{ \"active\": false }");
		oauth2_nv_list_free(log, params);
		goto end;
	}

error:

	rv = oauth2_strdup("problem");

end:

	return rv;
}

#define MY_CACHE_OPTIONS "options=max_entries%3D10"

START_TEST(test_oauth2_verify_jwks_uri)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt =
	    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0."
	    "eyJzY29wZSI6W10sImNsaWVudF9pZF9uYW1lIjoicm9fY2xpZW50IiwiYWdpZCI6Im"
	    "4zak1UazdXSDVVSU9FTWNEZEZPSVR5eFZ2VW1XRHVyIiwiT3JnTmFtZSI6IlBpbmcg"
	    "SWRlbnRpdHkgQ29ycG9yYXRpb24iLCJjbmYiOnsieDV0I1MyNTYiOiJsNnU5S1VDZ0"
	    "I2UHpHdklpTS0tWEYwTHF3N1ZYejdvQWtoUkhhbEZqOGkwIn0sIlVzZXJuYW1lIjoi"
	    "am9lIiwiZXhwIjoxNTQyMTI5NzgzfQ.MUghlaVxy5ij3HODBl6spAA-h6W7D-"
	    "PoKyhDfR5DnODQqwb5zaqba2pWyJ0d6-4AQfQ6dIe0jfwQeUrPTu2DZLtk3H-"
	    "noCSjtXrFV_RFNfz9kqdEXwkVZAX8H_ySrYFcAx3Ac9C8bZzjRUM6c4emql-"
	    "I6T1fVGqO_"
	    "bVUsWbPmPtNanq3UyqTrlDwQ6weO0ZbLH9tcDpZD4ojNCJjkHa3lvjwYzPNwlAI6a_"
	    "DGng-7rgrobhOiaAgBAwLhq9fvTtM2MWNmWXmUCymq3nGqG_d_t5i_"
	    "x7Zf28T3ejzEX-ETefpTENX7BJ57-vQbAeECRTIo_LhzKTaDkiZWpf6JgraQg";
	json_t *json_payload = NULL;
	const char *rv = NULL;
	char *url = NULL;

	url = oauth2_stradd(NULL, oauth2_check_http_base_url(),
			    get_jwks_uri_path, NULL);
	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "jwks_uri", url,
	    "verify.exp=skip&verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	oauth2_mem_free(url);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_eckey_uri)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt =
	    "eyJ0eXAiOiJKV1QiLCJraWQiOiIwOWQ0ZmExNy0yMjNlLTQwZmEtYjI4MC04OTRlOD"
	    "QzZDcwMWYiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29v"
	    "Z2xlLmNvbSIsImNsaWVudCI6IjY4NjMwMzIzMzEzMS1wZjA4b3J2YzVyY3BmaXQwdm"
	    "xxNW82dWg0N3UyZW5mZy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInNpZ25l"
	    "ciI6ImFybjphd3M6ZWxhc3RpY2xvYWRiYWxhbmNpbmc6ZXUtY2VudHJhbC0xOjAwNj"
	    "E3NTk0MDQ5NDpsb2FkYmFsYW5jZXIvYXBwL2JhbGFuY2VyMS8xODE3NThhZTJiMGMz"
	    "ZWRlIiwiZXhwIjoxNTQyMDQ1Mzk5fQ==."
	    "ewogICJzdWIiOiAiMTA5NzE2NDkyNjgxNjg2MTcyOTY5IiwKICAibmFtZSI6ICJIYW"
	    "5zIFphbmRiZWx0IiwKICAiZ2l2ZW5fbmFtZSI6ICJIYW5zIiwKICAiZmFtaWx5X25h"
	    "bWUiOiAiWmFuZGJlbHQiLAogICJwcm9maWxlIjogImh0dHBzOi8vcGx1cy5nb29nbG"
	    "UuY29tLzEwOTcxNjQ5MjY4MTY4NjE3Mjk2OSIsCiAgInBpY3R1cmUiOiAiaHR0cHM6"
	    "Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1pOUc3U1V2S1FETS9BQUFBQUFBQU"
	    "FBSS9BQUFBQUFBQUFBQS9zeEFzTk5FVlJWZy9waG90by5qcGciCn0=."
	    "AlH8PGya9avWoGVkWOFWbMNiLdpSDQZqP-"
	    "OuGfIXHw1CZWjxfJInXYiRsKRZlvlXJA5fguaeNKZ1Q_RyDjNqRg==";
	json_t *json_payload = NULL;
	const char *rv = NULL;
	char *url = NULL;

	url = oauth2_stradd(NULL, oauth2_check_http_base_url(),
			    get_eckey_url_path, NULL);
	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "eckey_uri", url, "verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	oauth2_mem_free(url);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_token_introspection)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	json_t *json_payload = NULL;
	const char *rv = NULL;
	char *url = NULL;

	url = oauth2_stradd(NULL, oauth2_check_http_base_url(),
			    post_introspection_path, NULL);

	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "introspect", url,
	    "introspect.ssl_verify=false&verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, "bogus", &json_payload);
	ck_assert_int_eq(rc, false);
	json_decref(json_payload);

	rc =
	    oauth2_token_verify(log, verify, valid_access_token, &json_payload);
	ck_assert_int_eq(rc, true);
	json_decref(json_payload);

	// get it from the cache
	rc =
	    oauth2_token_verify(log, verify, valid_access_token, &json_payload);
	ck_assert_int_eq(rc, true);
	json_decref(json_payload);

	oauth2_cfg_token_verify_free(log, verify);
	oauth2_mem_free(url);
}
END_TEST

START_TEST(test_oauth2_verify_token_plain)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
		    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
		    "sQOVoEtkQlgy8UwlPOi5YWSdGAkRn80JqT53RdktIms";
	json_t *json_payload = NULL;
	const char *rv = NULL;

	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "plain", "mysecret",
	    "kid=mykid&verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_token_base64)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
		    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
		    "kEm7kPCWXNn-p4cRSDAuO-htYx8hpq_7imIhMlig5So";
	json_t *json_payload = NULL;
	const char *rv = NULL;

	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "base64",
	    "YW5vdGhlcnNlY3JldA==", "verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_token_base64url)
{
	// https://tools.ietf.org/html/rfc7515#appendix-A with iat/exp
	// validation set to false
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
		    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly"
		    "9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-"
		    "mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	json_t *json_payload = NULL;
	const char *rv = NULL;

	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "base64url",
	    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-"
	    "1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
	    "verify.exp=skip&verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_token_hex)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
		    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
		    "ZdF3p7DBVz50evb9_eaY6euUtYikb6NTF7QHO6OTbGg";
	json_t *json_payload = NULL;
	const char *rv = NULL;

	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "hex", "6d797468697264736563726574",
	    "verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_token_pem)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt =
	    "eyJhbGciOiJSUzI1NiJ9."
	    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
	    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
	    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
	    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
	    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
	    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
	    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
	    "p0igcN_IoypGlUPQGe77Rw";
	json_t *json_payload = NULL;
	const char *rv = NULL;
	char *pem =
	    "-----BEGIN CERTIFICATE-----\n"
	    "MIICwzCCAaugAwIBAgIBADANBgkqhkiG9w0BAQQFADAlMQswCQYDVQQGEwJOTDEW\n"
	    "MBQGA1UEAwwNWm1hcnRab25lIElBTTAeFw0xOTAyMDcxOTI4MTFaFw0yMDAyMDcx\n"
	    "OTI4MTFaMCUxCzAJBgNVBAYTAk5MMRYwFAYDVQQDDA1abWFydFpvbmUgSUFNMIIB\n"
	    "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAofgWCuLjybRlzo0tZWJjNiuS\n"
	    "fb4p4fAkd/wWJcyQoTbji9k0l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEzP1Pt\n"
	    "0Bm4d4QlL+yRT+SFd2lZS+pCgNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo9wGz\n"
	    "jb/7OMg0LOL+bSf63kpaSHSXndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTBEMa2\n"
	    "R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxXFvUK\n"
	    "+DWNmoudF8NAco9/h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQID\n"
	    "AQABMA0GCSqGSIb3DQEBBAUAA4IBAQB8USZJ2O2um7QXYKJmI1YpeV1UCoqwl8zs\n"
	    "Ow6oMxppGRd8ZiOI4N+fYvRkZmdLDlvg/Xww0Z6sNT0HDlS0otbUhiYBg9fQb44v\n"
	    "Rx3lLXeziHoprzP/SApf5lFUJmzvfbsyKKRFsmkpGWbtkWKDHxk1BA/4symkoifC\n"
	    "OE8+GbbdaDXthPDEsrLNnTpH5mLrWZ4+Ulp7FQiB3okXnL/wasiMufRZdEhUPLdP\n"
	    "KS/Ch2wudSukzgin9K0GsvdM64I70tLyHRPtkIAorm5RwgGJvO5lHD/2W1hjIun0\n"
	    "aItLpLaBsJJKaMxUVbt6pGopRRQnCHscUxKZZEJDm6Qjiuw66iUW\n"
	    "-----END CERTIFICATE-----\n";

	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "pem", pem,
	    "verify.exp=skip&verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_token_pubkey)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	char *jwt =
	    "eyJhbGciOiJSUzI1NiJ9."
	    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
	    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
	    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
	    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
	    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
	    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
	    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
	    "p0igcN_IoypGlUPQGe77Rw";
	json_t *json_payload = NULL;
	const char *rv = NULL;
	char *pubkey =
	    "-----BEGIN PUBLIC KEY-----\n"
	    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAofgWCuLjybRlzo0tZWJj\n"
	    "NiuSfb4p4fAkd/wWJcyQoTbji9k0l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEz\n"
	    "P1Pt0Bm4d4QlL+yRT+SFd2lZS+pCgNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo\n"
	    "9wGzjb/7OMg0LOL+bSf63kpaSHSXndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTB\n"
	    "EMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxX\n"
	    "FvUK+DWNmoudF8NAco9/h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXp\n"
	    "oQIDAQAB\n"
	    "-----END PUBLIC KEY-----";

	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "pubkey", pubkey,
	    "verify.exp=skip&verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);

	oauth2_cfg_token_verify_free(log, verify);
	json_decref(json_payload);
}
END_TEST

START_TEST(test_oauth2_verify_token_metadata)
{
	bool rc = false;
	oauth2_cfg_token_verify_t *verify = NULL;
	json_t *json_payload = NULL;
	const char *rv = NULL;
	char *url = NULL;

	url = oauth2_stradd(NULL, oauth2_check_http_base_url(), metadata_path,
			    NULL);

	// TODO: make max_entries=5 the default for the shm cache of metadata
	// URIs
	rv = oauth2_cfg_token_verify_add_options(
	    log, &verify, "metadata", url,
	    "metadata.cache." MY_CACHE_OPTIONS
	    "&introspect.cache." MY_CACHE_OPTIONS
	    "&verify.exp=skip&verify.cache." MY_CACHE_OPTIONS);
	ck_assert_ptr_eq(rv, NULL);

	// reference token

	rc = oauth2_token_verify(log, verify, "bogus", &json_payload);
	ck_assert_int_eq(rc, false);
	json_decref(json_payload);

	rc =
	    oauth2_token_verify(log, verify, valid_access_token, &json_payload);
	ck_assert_int_eq(rc, true);
	json_decref(json_payload);
	// get it from the cache
	rc =
	    oauth2_token_verify(log, verify, valid_access_token, &json_payload);
	ck_assert_int_eq(rc, true);
	json_decref(json_payload);

	// jwt token

	char *jwt =
	    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0."
	    "eyJzY29wZSI6W10sImNsaWVudF9pZF9uYW1lIjoicm9fY2xpZW50IiwiYWdpZCI6Im"
	    "4zak1UazdXSDVVSU9FTWNEZEZPSVR5eFZ2VW1XRHVyIiwiT3JnTmFtZSI6IlBpbmcg"
	    "SWRlbnRpdHkgQ29ycG9yYXRpb24iLCJjbmYiOnsieDV0I1MyNTYiOiJsNnU5S1VDZ0"
	    "I2UHpHdklpTS0tWEYwTHF3N1ZYejdvQWtoUkhhbEZqOGkwIn0sIlVzZXJuYW1lIjoi"
	    "am9lIiwiZXhwIjoxNTQyMTI5NzgzfQ.MUghlaVxy5ij3HODBl6spAA-h6W7D-"
	    "PoKyhDfR5DnODQqwb5zaqba2pWyJ0d6-4AQfQ6dIe0jfwQeUrPTu2DZLtk3H-"
	    "noCSjtXrFV_RFNfz9kqdEXwkVZAX8H_ySrYFcAx3Ac9C8bZzjRUM6c4emql-"
	    "I6T1fVGqO_"
	    "bVUsWbPmPtNanq3UyqTrlDwQ6weO0ZbLH9tcDpZD4ojNCJjkHa3lvjwYzPNwlAI6a_"
	    "DGng-7rgrobhOiaAgBAwLhq9fvTtM2MWNmWXmUCymq3nGqG_d_t5i_"
	    "x7Zf28T3ejzEX-ETefpTENX7BJ57-vQbAeECRTIo_LhzKTaDkiZWpf6JgraQg";

	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);
	json_decref(json_payload);
	// get it from the cache
	rc = oauth2_token_verify(log, verify, jwt, &json_payload);
	ck_assert_int_eq(rc, true);
	json_decref(json_payload);

	oauth2_cfg_token_verify_free(log, verify);
	oauth2_mem_free(url);
}
END_TEST

Suite *oauth2_check_oauth2_suite()
{
	Suite *s = suite_create("oauth2");
	TCase *c = tcase_create("core");

	liboauth2_check_register_http_callbacks(oauth2_check_http_base_path(),
						oauth2_check_oauth2_serve_get,
						oauth2_check_oauth2_serve_post);

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_oauth2_auth_client_secret_basic);
	tcase_add_test(c, test_oauth2_auth_client_secret_post);
	tcase_add_test(c, test_oauth2_auth_client_secret_jwt);
	tcase_add_test(c, test_oauth2_auth_private_key_jwt);
	tcase_add_test(c, test_oauth2_auth_client_cert);
	tcase_add_test(c, test_oauth2_auth_http_basic);
	tcase_add_test(c, test_oauth2_auth_none);
	tcase_add_test(c, test_oauth2_verify_clone);
	tcase_add_test(c, test_oauth2_verify_jwks_uri);
	tcase_add_test(c, test_oauth2_verify_eckey_uri);
	tcase_add_test(c, test_oauth2_verify_token_introspection);
	tcase_add_test(c, test_oauth2_verify_token_plain);
	tcase_add_test(c, test_oauth2_verify_token_base64);
	tcase_add_test(c, test_oauth2_verify_token_base64url);
	tcase_add_test(c, test_oauth2_verify_token_hex);
	tcase_add_test(c, test_oauth2_verify_token_pem);
	tcase_add_test(c, test_oauth2_verify_token_pubkey);
	tcase_add_test(c, test_oauth2_verify_token_metadata);

	suite_add_tcase(s, c);

	return s;
}
