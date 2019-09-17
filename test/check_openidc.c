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

#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/openidc.h"
#include "oauth2/util.h"

#include <check.h>
#include <stdlib.h>

static oauth2_log_t *log = 0;

static void setup(void)
{
	log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(log);
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

	oauth2_debug(log, "## enter");

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

	oauth2_debug(log, "## return: %d", rc);

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
		if (oauth2_parse_form_encoded_params(log, data, &params) ==
		    false)
			goto error;
		code = oauth2_nv_list_get(log, params, "code");
		if (code == NULL)
			goto error;

		if (_oauth2_check_openidc_idtoken_create(
			log, oauth2_jwk_rsa_get(), "RS256", "myclient",
			"myclient", &id_token) == false)
			goto error;

		rv =
		    oauth2_stradd(NULL, "{ \"id_token\": \"", id_token, "\", ");
		rv = oauth2_stradd(rv, "\"access_token\": \"", "xxxx", "\" }");

		oauth2_mem_free(id_token);
		oauth2_nv_list_free(log, params);
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

	c = oauth2_cfg_openidc_init(log);
	r = oauth2_http_request_init(log);

	rc = oauth2_cfg_openidc_redirect_uri_set(
	    log, c, "https://example.org/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.org/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_cfg_openidc_redirect_uri_set(
	    log, c, "https://example.com/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_cfg_openidc_redirect_uri_set(log, c, "/redirect_uri");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_ptr_eq(value, NULL);

	rc = oauth2_http_request_header_set(log, r, "Host", "example.com");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get(log, c, r);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	p = oauth2_openidc_provider_init(log);
	ck_assert_ptr_ne(p, NULL);

	value = oauth2_cfg_openidc_redirect_uri_get_iss(log, c, r, p);
	// ck_assert_ptr_eq(value, NULL);
	ck_assert_str_eq(value, "https://example.com/redirect_uri");
	oauth2_mem_free(value);

	rc = oauth2_openidc_provider_issuer_set(log, p, "jan");
	ck_assert_int_eq(rc, true);
	value = oauth2_cfg_openidc_redirect_uri_get_iss(log, c, r, p);
	ck_assert_str_eq(value, "https://example.com/redirect_uri?iss=jan");
	oauth2_mem_free(value);

	oauth2_openidc_provider_free(log, p);
	oauth2_http_request_free(log, r);
	oauth2_cfg_openidc_free(log, c);
}
END_TEST

bool test_openidc_provider_resolver(oauth2_log_t *log,
				    const oauth2_http_request_t *request,
				    oauth2_openidc_provider_t **provider)
{
	// TODO: free/global
	*provider = oauth2_openidc_provider_init(log);
	oauth2_openidc_provider_issuer_set(log, *provider,
					   "https://op.example.org");
	oauth2_openidc_provider_authorization_endpoint_set(
	    log, *provider, "https://op.example.org/authorize");
	oauth2_openidc_provider_scope_set(log, *provider, "openid");
	oauth2_openidc_provider_client_id_set(log, *provider, "myclient");
	oauth2_openidc_provider_client_secret_set(log, *provider, "secret");
	return true;
}

OAUTH2_CHECK_HTTP_PATHS

START_TEST(test_openidc_handle)
{
	bool rc = false;
	oauth2_cfg_openidc_t *c = NULL;
	oauth2_http_request_t *r = NULL;
	oauth2_http_response_t *response = NULL;
	const char *location = NULL;
	char *state = NULL, *state_cookie_name = NULL, *state_cookie = NULL,
	     *query_str = NULL;
	char *token_endpoint = oauth2_stradd(NULL, oauth2_check_http_base_url(),
					     token_endpoint_path, NULL);
	char *jwks_uri = oauth2_stradd(NULL, oauth2_check_http_base_url(),
				       jwks_uri_path, NULL);
	char *metadata = oauth2_strdup("{ "
				       "\"issuer\": \"https://op.example.org\","
				       "\"authorization_endpoint\": "
				       "\"https://op.example.org/authorize\",");
	metadata = oauth2_stradd(metadata, "\"token_endpoint\": \"",
				 token_endpoint, "\",");
	metadata = oauth2_stradd(metadata, "\"jwks_uri\": \"", jwks_uri, "\",");
	metadata =
	    oauth2_stradd(metadata,
			  "\"token_endpoint_auth\": \"client_secret_post\","
			  "\"client_id\": \"myclient\","
			  "\"client_secret\": \"secret1234\","
			  "\"scope\": \"openid profile\","
			  "\"ssl_verify\": false"
			  "}",
			  NULL, NULL);
	json_t *claims = NULL;

	c = oauth2_cfg_openidc_init(log);
	r = oauth2_http_request_init(log);

	oauth2_cfg_openidc_passphrase_set(log, c, "mypassphrase1234");
	oauth2_cfg_openidc_provider_resolver_set_options(log, c, "string",
							 metadata, NULL);

	rc = oauth2_http_request_path_set(log, r, "/secure");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);

	rc = oauth2_openidc_handle(log, c, r, &response, &claims);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, response);

	ck_assert_uint_eq(oauth2_http_response_status_code_get(log, response),
			  302);
	location = oauth2_http_response_header_get(log, response, "Location");
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
	    oauth2_http_response_header_get(log, response, "Set-Cookie"));
	ck_assert_ptr_ne(NULL, state_cookie);
	ck_assert_ptr_ne(NULL, strstr(state_cookie, state_cookie_name));

	oauth2_http_response_free(log, response);
	response = NULL;
	oauth2_http_request_free(log, r);

	r = oauth2_http_request_init(log);
	rc = oauth2_http_request_path_set(log, r,
					  "/openid-connect/redirect_uri");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Host", "app.example.org");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Accept", "text/html");
	ck_assert_int_eq(rc, true);
	rc = oauth2_http_request_header_set(log, r, "Cookie", state_cookie);
	ck_assert_int_eq(rc, true);

	query_str = oauth2_stradd(NULL, "code=4321&state", "=", state);
	rc = oauth2_http_request_query_set(log, r, query_str);
	ck_assert_int_eq(rc, true);

	rc = oauth2_openidc_handle(log, c, r, &response, &claims);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(NULL, response);
	ck_assert_uint_eq(oauth2_http_response_status_code_get(log, response),
			  302);

	oauth2_mem_free(state_cookie);

	// TODO: there's a session Set-Cookie header now as well
	//	state_cookie = oauth2_strdup(
	//	    oauth2_http_response_header_get(log, response,
	//"Set-Cookie")); 	ck_assert_ptr_ne(NULL, state_cookie);
	//	ck_assert_ptr_ne(NULL, strstr(state_cookie,
	//				      "expires=Thu, 01 Jan 1970 00:00:00
	// GMT"));

	location = oauth2_http_response_header_get(log, response, "Location");
	ck_assert_ptr_ne(NULL, response);
	ck_assert_int_eq(strcmp(location, "https://app.example.org/secure"), 0);

	oauth2_http_response_free(log, response);
	oauth2_http_request_free(log, r);

	json_decref(claims);
	oauth2_mem_free(state);
	oauth2_mem_free(query_str);
	oauth2_mem_free(state_cookie_name);
	//	oauth2_mem_free(state_cookie);
	oauth2_mem_free(token_endpoint);
	oauth2_mem_free(metadata);

	oauth2_cfg_openidc_free(log, c);
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
	tcase_add_test(c, test_openidc_handle);

	suite_add_tcase(s, c);

	return s;
}
