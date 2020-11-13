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

#include "check_liboauth2.h"

#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/openidc.h"
#include "oauth2/util.h"

#include "cfg_int.h"
#include "openidc_int.h"

#include <check.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static oauth2_log_t *_log = 0;

static char *_openidc_metadata = NULL;

OAUTH2_CHECK_HTTP_PATHS

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

void oauth2_check_openidc_cleanup()
{
	oauth2_check_http_base_free();
}

static void teardown(void)
{
	oauth2_shutdown(_log);
	if (_openidc_metadata != NULL) {
		oauth2_mem_free(_openidc_metadata);
		_openidc_metadata = NULL;
	}
}

static char *jwk_rsa_str =
    "{"
    "\"kty\": \"RSA\","
    "\"kid\": \"bilbo.baggins@hobbiton.example\","
    "\"use\": \"sig\","
    "\"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
    "HdrNP5zw\","
    "\"e\": \"AQAB\","
    "\"d\": \"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e"
    "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld"
    "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b"
    "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU"
    "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj"
    "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc"
    "OpBrQzwQ\","
    "\"p\": \"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR"
    "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG"
    "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8"
    "bUq0k\","
    "\"q\": \"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT"
    "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an"
    "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0"
    "s7pFc\","
    "\"dp\": \"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q"
    "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn"
    "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX"
    "59ehik\","
    "\"dq\": \"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr"
    "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK"
    "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK"
    "T1cYF8\","
    "\"qi\": \"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N"
    "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh"
    "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP"
    "z8aaI4\""
    "}";

static cjose_jwk_t *jwk_rsa = NULL;

static char *jwks_uri_path = "/jwks_uri";
static char *token_endpoint_path = "/token";
static char *userinfo_endpoint_path = "/userinfo";

static cjose_jwk_t *oauth2_jwk_rsa_get()
{
	cjose_err err;
	if (jwk_rsa == NULL) {
		jwk_rsa =
		    cjose_jwk_import(jwk_rsa_str, strlen(jwk_rsa_str), &err);
		if (jwk_rsa == NULL) {
			fprintf(
			    stderr,
			    "## cjose_jwk_import failed: %s (%s:%s:%ld) \n%s\n",
			    err.message, err.file, err.function, err.line,
			    jwk_rsa_str);
		}
	}
	return jwk_rsa;
}

static char *oauth2_check_openidc_serve_get(const char *request)
{
	char *rv = NULL, *s = NULL;
	cjose_err err;
	if (strncmp(request, jwks_uri_path, strlen(jwks_uri_path)) == 0) {
		// TODO: static
		s = cjose_jwk_to_json(oauth2_jwk_rsa_get(), false, &err);
		rv = oauth2_stradd(NULL, "{ \"keys\": [ ", s, " ] }");
		cjose_get_dealloc()(s);
	} else if (strncmp(request, userinfo_endpoint_path,
			   strlen(userinfo_endpoint_path)) == 0) {
		rv = oauth2_strdup("{ \"sub\": \"myclient\", "
				   "\"myuserinfoclaim\": \"somevalue\" }");
	} else {
		rv = oauth2_strdup("problem");
	}
	return rv;
}

static bool
_oauth2_check_openidc_idtoken_create(oauth2_log_t *log, cjose_jwk_t *jwk,
				     const char *alg, const char *client_id,
				     const char *aud, char **id_token)
{

	bool rc = false;
	char *payload = NULL;
	json_t *json = NULL;
	cjose_header_t *hdr = NULL;
	cjose_jws_t *jws = NULL;
	const char *jwt = NULL;
	cjose_err err;

	oauth2_debug(_log, "## enter");

	json = json_object();
	json_object_set_new(json, OAUTH2_JOSE_JWT_ISS, json_string(client_id));
	json_object_set_new(json, OAUTH2_JOSE_JWT_SUB, json_string(client_id));
	json_object_set_new(json, OAUTH2_JOSE_JWT_AUD, json_string(aud));
	json_object_set_new(json, OAUTH2_JOSE_JWT_EXP,
			    json_integer(oauth2_time_now_sec() + 60));
	json_object_set_new(json, OAUTH2_JOSE_JWT_IAT,
			    json_integer(oauth2_time_now_sec()));
	payload = json_dumps(json, JSON_PRESERVE_ORDER | JSON_COMPACT);

	hdr = cjose_header_new(&err);
	if (hdr == NULL) {
		oauth2_error(_log, "cjose_header_new failed: %s", err.message);
		goto end;
	}
	if (cjose_header_set(hdr, CJOSE_HDR_ALG, alg, &err) == false) {
		oauth2_error(_log, "cjose_header_set %s:%s failed: %s",
			     CJOSE_HDR_ALG, alg, err.message);
		goto end;
	}
	if (cjose_header_set(hdr, OAUTH2_JOSE_HDR_TYP, OAUTH2_JOSE_HDR_TYP_JWT,
			     &err) == false) {
		oauth2_error(_log, "cjose_header_set %s:%s failed: %s",
			     OAUTH2_JOSE_HDR_TYP, OAUTH2_JOSE_HDR_TYP_JWT,
			     err.message);
		goto end;
	}

	jws = cjose_jws_sign(jwk, hdr, (const uint8_t *)payload,
			     strlen(payload), &err);
	if (jws == NULL) {
		oauth2_error(_log, "cjose_jws_sign failed: %s", err.message);
		goto end;
	}

	if (cjose_jws_export(jws, &jwt, &err) == false) {
		oauth2_error(_log, "cjose_jws_export failed: %s", err.message);
		goto end;
	}

	*id_token = oauth2_strdup(jwt);

	rc = true;

end:

	if (json)
		json_decref(json);
	if (payload)
		free(payload);
	if (hdr)
		cjose_header_release(hdr);
	if (jws)
		cjose_jws_release(jws);

	oauth2_debug(_log, "## return: %d", rc);

	return rc;
}

static char *oauth2_check_openidc_serve_post(const char *request)
{
	oauth2_nv_list_t *params = NULL;
	char *data = NULL;
	const char *code = NULL;
	const char *sep = "****";
	char *rv = NULL;
	char *id_token = NULL;

	if (strncmp(request, token_endpoint_path,
		    strlen(token_endpoint_path)) == 0) {
		request += strlen(token_endpoint_path) + 5;
		data = strstr(request, sep);
		if (data == NULL)
			goto error;
		data += strlen(sep);
		if (oauth2_parse_form_encoded_params(_log, data, &params) ==
		    false)
			goto error;
		code = oauth2_nv_list_get(_log, params, "code");
		if (code == NULL)
			goto error;

		if (_oauth2_check_openidc_idtoken_create(
			_log, oauth2_jwk_rsa_get(), "RS256", "myclient",
			"myclient", &id_token) == false)
			goto error;

		rv =
		    oauth2_stradd(NULL, "{ \"id_token\": \"", id_token, "\", ");
		rv = oauth2_stradd(rv, "\"access_token\": \"", "xxxx", "\" }");

		oauth2_mem_free(id_token);
		oauth2_nv_list_free(_log, params);
		goto end;
	}

error:

	rv = oauth2_strdup("problem");

end:

	return rv;
}

START_TEST(test_openidc_cfg)
{
	bool rc = false;
	oauth2_cfg_openidc_t *c = NULL;
	oauth2_http_request_t *r = NULL;
	oauth2_openidc_provider_t *p = NULL;
	char *value = NULL;

	c = oauth2_cfg_openidc_init(_log);
	r = oauth2_http_request_init(_log);

	rc = oauth2_cfg_openidc_redirect_uri_set(
	    _log, c, "https://example.org/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(_log, c, r);
	ck_assert_str_eq(value, "https://example.org/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_cfg_openidc_redirect_uri_set(
	    _log, c, "https://example.com/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(_log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_cfg_openidc_redirect_uri_set(_log, c, "/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(_log, c, r);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_http_request_header_set(_log, r, "Host", "example.com");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(_log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	p = oauth2_openidc_provider_init(_log);
	ck_assert_ptr_ne(p, NULL);

	value = oauth2_cfg_openidc_redirect_uri_get_iss(_log, c, r, p);
	// ck_assert_ptr_eq(value, NULL);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_openidc_provider_issuer_set(_log, p, "jan");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get_iss(_log, c, r, p);
	ck_assert_str_eq(value, "https://example.com/redirect_uri?iss=jan");
	oauth2_mem_free(value);

	oauth2_openidc_provider_free(_log, p);
	oauth2_http_request_free(_log, r);
	oauth2_cfg_openidc_free(_log, c);
}
END_TEST

static char *test_openidc_metadata_get()
{

	if (_openidc_metadata)
		goto end;

	char *token_endpoint = oauth2_stradd(NULL, oauth2_check_http_base_url(),
					     token_endpoint_path, NULL);
	char *userinfo_endpoint = oauth2_stradd(
	    NULL, oauth2_check_http_base_url(), userinfo_endpoint_path, NULL);
	char *jwks_uri = oauth2_stradd(NULL, oauth2_check_http_base_url(),
				       jwks_uri_path, NULL);
	_openidc_metadata =
	    oauth2_strdup("{ "
			  "\"issuer\": \"https://op.example.org\","
			  "\"authorization_endpoint\": "
			  "\"https://op.example.org/authorize\",");
	_openidc_metadata = oauth2_stradd(
	    _openidc_metadata, "\"token_endpoint\": \"", token_endpoint, "\",");
	_openidc_metadata =
	    oauth2_stradd(_openidc_metadata, "\"userinfo_endpoint\": \"",
			  userinfo_endpoint, "\",");
	_openidc_metadata = oauth2_stradd(_openidc_metadata, "\"jwks_uri\": \"",
					  jwks_uri, "\" }");

	oauth2_mem_free(token_endpoint);
	oauth2_mem_free(jwks_uri);
	oauth2_mem_free(userinfo_endpoint);

end:

	return _openidc_metadata;
}

START_TEST(test_openidc_proto_state)
{
	bool rc = false;
	json_t *json = NULL;
	oauth2_cfg_openidc_t *c = NULL;
	oauth2_http_request_t *r = oauth2_http_request_init(_log);
	oauth2_http_response_t *response = NULL;
	oauth2_openidc_provider_t *provider = NULL;
	char *value = NULL;
	const char *cookie = NULL;

	c = oauth2_cfg_openidc_init(_log);
	oauth2_cfg_openidc_provider_resolver_set_options(
	    _log, c, "string", test_openidc_metadata_get(), NULL);

	oauth2_openidc_proto_state_t *p1 =
	    oauth2_openidc_proto_state_init(_log);
	ck_assert_ptr_ne(p1, NULL);

	rc = oauth2_openidc_proto_state_set(_log, p1, "one", "string");
	ck_assert_int_eq(rc, true);
	rc = oauth2_openidc_proto_state_set_int(_log, p1, "two", 2);
	ck_assert_int_eq(rc, true);

	json = oauth2_openidc_proto_state_json_get(p1);
	ck_assert_ptr_ne(json, NULL);
	ck_assert_str_eq(json_string_value(json_object_get(json, "one")),
			 "string");
	ck_assert_int_eq(json_integer_value(json_object_get(json, "two")), 2);

	rc = oauth2_openidc_proto_state_set(
	    _log, p1, _OAUTH2_OPENIDC_PROTO_STATE_KEY_ISSUER,
	    "https://op.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_openidc_proto_state_set_int(
	    _log, p1, _OAUTH2_OPENIDC_PROTO_STATE_KEY_TIMESTAMP,
	    oauth2_time_now_sec());
	ck_assert_int_eq(rc, true);
	rc = oauth2_openidc_proto_state_set(
	    _log, p1, _OAUTH2_OPENIDC_PROTO_STATE_KEY_TARGET_LINK_URI,
	    "https://example.org/secure");
	rc = _oauth2_openidc_state_validate(_log, c, r, p1, &provider);
	ck_assert_int_eq(rc, true);
	rc = oauth2_openidc_proto_state_target_link_uri_get(_log, p1, &value);
	ck_assert_int_eq(rc, true);
	ck_assert_str_eq(value, "https://example.org/secure");
	oauth2_mem_free(value);
	value = NULL;

	oauth2_openidc_proto_state_t *p2 =
	    oauth2_openidc_proto_state_clone(_log, p1);
	ck_assert_ptr_ne(c, NULL);

	json = oauth2_openidc_proto_state_json_get(p2);
	ck_assert_ptr_ne(json, NULL);
	ck_assert_str_eq(json_string_value(json_object_get(json, "one")),
			 "string");
	ck_assert_int_eq(json_integer_value(json_object_get(json, "two")), 2);

	oauth2_openidc_proto_state_free(_log, p2);
	oauth2_openidc_proto_state_free(_log, p1);

	oauth2_http_request_scheme_set(_log, r, "https");
	oauth2_http_request_hostname_set(_log, r, "example.org");
	oauth2_http_request_path_set(_log, r, "/secure");

	response = oauth2_http_response_init(_log);
	rc = _oauth2_openidc_state_cookie_set(_log, c, provider, r, response,
					      "1234");
	ck_assert_int_eq(rc, true);
	cookie = oauth2_http_response_header_get(_log, response, "Set-Cookie");
	ck_assert_ptr_ne(strstr(cookie, "openidc_state_1234="), NULL);

	oauth2_openidc_proto_state_t *p3 = NULL;
	oauth2_http_request_header_set(_log, r, "Cookie", cookie);
	rc =
	    _oauth2_openidc_state_cookie_get(_log, c, r, response, "1234", &p3);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(p3, NULL);
	rc = oauth2_openidc_proto_state_target_link_uri_get(_log, p3, &value);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(value, NULL);
	ck_assert_str_eq(value, "https://example.org/secure");
	oauth2_mem_free(value);
	value = NULL;
	oauth2_openidc_proto_state_free(_log, p3);

	oauth2_openidc_provider_free(_log, provider);
	oauth2_http_response_free(_log, response);
	oauth2_http_request_free(_log, r);
	oauth2_cfg_openidc_free(_log, c);
}
END_TEST

static void _test_openidc_resolve_to_false(oauth2_cfg_openidc_t *c,
					   oauth2_http_request_t *r,
					   const char *metadata)
{
	bool rc = false;
	char *rv = NULL;
	oauth2_openidc_provider_t *provider = NULL;

	rv = oauth2_cfg_openidc_provider_resolver_set_options(_log, c, "string",
							      metadata, NULL);
	ck_assert_ptr_eq(rv, NULL);
	rc = _oauth2_openidc_provider_resolve(_log, c, r, NULL, &provider);
	ck_assert_int_eq(rc, false);
	ck_assert_ptr_eq(NULL, provider);
}

START_TEST(test_openidc_resolver)
{
	bool rc = false;
	char *rv = NULL;
	oauth2_cfg_openidc_t *c = NULL;
	oauth2_http_request_t *r = NULL;
	oauth2_openidc_provider_t *provider = NULL;

	c = oauth2_cfg_openidc_init(_log);
	r = oauth2_http_request_init(_log);

	rv = oauth2_cfg_openidc_provider_resolver_set_options(
	    _log, c, "string", test_openidc_metadata_get(), NULL);
	ck_assert_ptr_eq(rv, NULL);

	rc = _oauth2_openidc_provider_resolve(_log, c, r, NULL, &provider);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, provider);
	ck_assert_str_eq("https://op.example.org",
			 oauth2_openidc_provider_issuer_get(_log, provider));
	oauth2_openidc_provider_free(_log, provider);
	provider = NULL;

	rv = oauth2_cfg_openidc_provider_resolver_set_options(
	    _log, c, "file", "./test/provider.json", NULL);
	ck_assert_ptr_eq(rv, NULL);

	rc = _oauth2_openidc_provider_resolve(_log, c, r, NULL, &provider);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, provider);
	ck_assert_str_eq("https://pingfed:9031",
			 oauth2_openidc_provider_issuer_get(_log, provider));

	ck_assert_ptr_ne(
	    NULL,
	    oauth2_openidc_provider_authorization_endpoint_get(_log, provider));
	ck_assert_ptr_ne(
	    NULL, oauth2_openidc_provider_token_endpoint_get(_log, provider));

	/*
	ck_assert_ptr_ne(NULL, oauth2_openidc_provider_token_endpoint_auth_get(
				   _log, provider));
	ck_assert_int_eq(
	    false, oauth2_openidc_provider_ssl_verify_get(_log, provider));
	    */
	ck_assert_ptr_ne(NULL,
			 oauth2_openidc_provider_jwks_uri_get(_log, provider));
	/*
	ck_assert_ptr_ne(NULL,
			 oauth2_openidc_provider_scope_get(_log, provider));
	ck_assert_ptr_ne(NULL,
			 oauth2_openidc_provider_client_id_get(_log, provider));
	ck_assert_ptr_ne(
	    NULL, oauth2_openidc_provider_client_secret_get(_log, provider));

	ck_assert_int_eq(
	    true, oauth2_openidc_provider_ssl_verify_set(_log, provider, true));
	    */
	ck_assert_int_eq(true,
			 oauth2_openidc_provider_authorization_endpoint_set(
			     _log, provider, "https://other.org/authorize"));
	ck_assert_int_eq(true, oauth2_openidc_provider_token_endpoint_set(
				   _log, provider, "https://other.org/token"));
	ck_assert_int_eq(true,
			 oauth2_openidc_provider_jwks_uri_set(
			     _log, provider, "https://other.org/jwks_uri"));
	/*
	ck_assert_int_eq(true, oauth2_openidc_provider_scope_set(
				   _log, provider, "openid profile other"));
	ck_assert_int_eq(true, oauth2_openidc_provider_client_id_set(
				   _log, provider, "someclientid"));
	ck_assert_int_eq(true, oauth2_openidc_provider_client_secret_set(
				   _log, provider, "someclientsecret"));
	*/
	oauth2_openidc_provider_free(_log, provider);
	provider = NULL;

	_test_openidc_resolve_to_false(c, r, NULL);
	_test_openidc_resolve_to_false(c, r, "");
	_test_openidc_resolve_to_false(c, r, "{");
	_test_openidc_resolve_to_false(c, r, "{}");
	_test_openidc_resolve_to_false(c, r, "{ \"issuer\": 0 }");
	_test_openidc_resolve_to_false(c, r,
				       "{ \"authorization_endpoint\": 1, "
				       "\"issuer\": \"https://example.org\" }");
	_test_openidc_resolve_to_false(
	    c, r,
	    "{ \"token_endpoint\": 1, \"authorization_endpoint\": "
	    "\"https://example.org/authorize\", \"issuer\": "
	    "\"https://example.org\" }");
	_test_openidc_resolve_to_false(
	    c, r,
	    "{ \"jwks_uri\": 0, \"token_endpoint\": "
	    "\"https://example.org/authorize\", \"authorization_endpoint\": "
	    "\"https://example.org/authorize\", \"issuer\": "
	    "\"https://example.org\" }");

	rv = oauth2_cfg_openidc_provider_resolver_set_options(_log, c, "dir",
							      NULL, NULL);
	ck_assert_ptr_eq(rv, NULL);
	rc = _oauth2_openidc_provider_resolve(_log, c, r, NULL, &provider);
	ck_assert_int_eq(rc, false);

	oauth2_http_request_free(_log, r);
	oauth2_cfg_openidc_free(_log, c);
}
END_TEST

static void _test_openidc_handle(oauth2_cfg_openidc_t *c)
{
	bool rc = false;
	oauth2_http_request_t *r = NULL;
	oauth2_http_response_t *response = NULL;
	const char *location = NULL;
	char *state = NULL, *state_cookie_name = NULL, *state_cookie = NULL,
	     *query_str = NULL, *session_cookie = NULL;
	json_t *claims = NULL;

	r = oauth2_http_request_init(_log);

	rc = oauth2_http_request_path_set(_log, r, "/secure");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);

	rc = oauth2_openidc_handle(_log, c, r, &response, &claims);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, response);

	ck_assert_uint_eq(oauth2_http_response_status_code_get(_log, response),
			  302);
	location = oauth2_http_response_header_get(_log, response, "Location");
	ck_assert_ptr_ne(NULL, strstr(location, "response_type=code"));
	ck_assert_ptr_ne(NULL,
			 strstr(location, "https://op.example.org/authorize"));
	state = strstr(location, "state=");
	ck_assert_ptr_ne(NULL, state);

	state += strlen("state=");
	state = oauth2_strdup(state);
	char *p = strstr(state, "&");
	if (p)
		*p = '\0';

	state_cookie_name = oauth2_stradd(NULL, "openidc_state_", state, NULL);

	state_cookie = oauth2_strdup(
	    oauth2_http_response_header_get(_log, response, "Set-Cookie"));
	ck_assert_ptr_ne(NULL, state_cookie);
	ck_assert_ptr_ne(NULL, strstr(state_cookie, state_cookie_name));

	json_decref(claims);
	oauth2_http_response_free(_log, response);
	response = NULL;
	oauth2_http_request_free(_log, r);

	r = oauth2_http_request_init(_log);
	rc = oauth2_http_request_path_set(_log, r,
					  "/openid-connect/redirect_uri");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Cookie", state_cookie);
	ck_assert_int_eq(rc, true);

	query_str = oauth2_stradd(NULL, "code=4321&state", "=", state);
	rc = oauth2_http_request_query_set(_log, r, query_str);
	ck_assert_int_eq(rc, true);

	rc = oauth2_openidc_handle(_log, c, r, &response, &claims);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, response);
	ck_assert_uint_eq(oauth2_http_response_status_code_get(_log, response),
			  302);

	oauth2_mem_free(state_cookie);

	state_cookie =
	    oauth2_strdup(oauth2_http_response_header_set_cookie_prefix_get(
		_log, response, state_cookie_name));
	ck_assert_ptr_ne(NULL, state_cookie);
	ck_assert_ptr_ne(NULL, strstr(state_cookie,
				      "expires=Thu, 01 Jan 1970 00:00:00 GMT"));

	location = oauth2_http_response_header_get(_log, response, "Location");
	ck_assert_ptr_ne(NULL, response);
	ck_assert_int_eq(strcmp(location, "https://app.example.org/secure"), 0);

	session_cookie =
	    oauth2_strdup(oauth2_http_response_header_set_cookie_prefix_get(
		_log, response, "openidc_session"));
	ck_assert_ptr_ne(NULL, session_cookie);

	json_decref(claims);
	oauth2_http_response_free(_log, response);
	oauth2_http_request_free(_log, r);

	r = oauth2_http_request_init(_log);
	rc = oauth2_http_request_path_set(_log, r, "/secure");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Cookie", session_cookie);
	ck_assert_int_eq(rc, true);

	rc = oauth2_openidc_handle(_log, c, r, &response, &claims);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, response);
	// TODO:
	ck_assert_uint_eq(oauth2_http_response_status_code_get(_log, response),
			  0);
	// ck_assert_ptr_ne(NULL,
	// oauth2_http_response_header_set_cookie_prefix_get(_log, response,
	// "openidc_session"));

	ck_assert_str_eq(
	    json_string_value(json_object_get(claims, "myuserinfoclaim")),
	    "somevalue");

	json_decref(claims);
	oauth2_http_request_free(_log, r);
	oauth2_http_response_free(_log, response);

	sleep(2);

	r = oauth2_http_request_init(_log);
	rc = oauth2_http_request_path_set(_log, r, "/secure");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(_log, r, "Cookie", session_cookie);
	ck_assert_int_eq(rc, true);

	response = NULL;
	rc = oauth2_openidc_handle(_log, c, r, &response, &claims);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, response);
	ck_assert_uint_eq(oauth2_http_response_status_code_get(_log, response),
			  302);

	oauth2_http_request_free(_log, r);
	oauth2_http_response_free(_log, response);

	oauth2_mem_free(state);
	oauth2_mem_free(query_str);
	oauth2_mem_free(state_cookie_name);
	oauth2_mem_free(state_cookie);
	oauth2_mem_free(session_cookie);
}

START_TEST(test_openidc_handle_cookie)
{
	oauth2_cfg_openidc_t *c = NULL;
	oauth2_cfg_session_t *session_cfg = NULL;

	c = oauth2_cfg_openidc_init(_log);

	session_cfg = oauth2_cfg_session_init(_log);
	oauth2_cfg_session_set_options(
	    _log, session_cfg, "cookie",
	    "name=short_cookie&inactivity_timeout=1");

	oauth2_cfg_openidc_provider_resolver_set_options(
	    _log, c, "string", test_openidc_metadata_get(),
	    "session=short_cookie");

	oauth2_openidc_client_set_options(
	    _log, c, "myclient",
	    "token_endpoint_auth_method=client_secret_post&client_id=myclient&"
	    "client_secret="
	    "mysecret&scope=openid%20profile&ssl_verify=false");

	_test_openidc_handle(c);

	oauth2_cfg_openidc_free(_log, c);
}
END_TEST

START_TEST(test_openidc_handle_cache)
{
	oauth2_cache_t *cache = NULL;
	oauth2_nv_list_t *params = NULL;
	oauth2_cfg_session_t *session_cfg = NULL;
	oauth2_cfg_openidc_t *c = NULL;
	char *rv = NULL;

	c = oauth2_cfg_openidc_init(_log);

	rv = oauth2_cfg_set_cache(_log, "shm", "name=memory&max_entries=5");
	ck_assert_ptr_eq(rv, NULL);
	cache = oauth2_cache_obtain(_log, NULL);
	ck_assert_ptr_ne(cache, NULL);

	session_cfg = oauth2_cfg_session_init(_log);
	oauth2_cfg_session_set_options(
	    _log, session_cfg, "cache",
	    "name=short_memory&cache=memory&inactivity_timeout=1");

	oauth2_cfg_openidc_provider_resolver_set_options(
	    _log, c, "string", test_openidc_metadata_get(),
	    "session=short_memory");

	oauth2_openidc_client_set_options(
	    _log, c, "myclient",
	    "token_endpoint_auth_method=client_secret_post&client_id=myclient&"
	    "client_secret="
	    "mysecret&scope=openid%20profile&ssl_verify=false");

	_test_openidc_handle(c);

	oauth2_nv_list_free(_log, params);
	oauth2_cfg_openidc_free(_log, c);
}
END_TEST

Suite *oauth2_check_openidc_suite()
{
	Suite *s = suite_create("openidc");
	TCase *c = tcase_create("core");

	liboauth2_check_register_http_callbacks(
	    oauth2_check_http_base_path(), oauth2_check_openidc_serve_get,
	    oauth2_check_openidc_serve_post);

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_openidc_cfg);
	tcase_add_test(c, test_openidc_proto_state);
	tcase_add_test(c, test_openidc_resolver);
	tcase_add_test(c, test_openidc_handle_cookie);
	tcase_add_test(c, test_openidc_handle_cache);

	suite_add_tcase(s, c);

	return s;
}
