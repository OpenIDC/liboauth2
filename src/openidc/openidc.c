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

#include "oauth2/openidc.h"
#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/oauth2.h"
#include "oauth2/session.h"

#include "cfg_int.h"
#include "openidc_int.h"

#define OAUTH2_STATE_LENGTH 16
#define OAUTH2_NONCE_LENGTH 16
#define OAUTH2_PKCE_LENGTH 48

static bool _oauth2_openidc_authenticate(oauth2_log_t *log,
					 const oauth2_cfg_openidc_t *cfg,
					 const oauth2_http_request_t *request,
					 oauth2_http_response_t **response)
{
	bool rc = false;
	oauth2_openidc_provider_t *provider = NULL;
	char *nonce = NULL, *state = NULL, *redirect_uri = NULL,
	     *location = NULL, *pkce = NULL, *code_challenge = NULL;
	oauth2_nv_list_t *params = oauth2_nv_list_init(log);
	char *client_id = NULL, *scope = NULL;
	unsigned char *dst = NULL;
	unsigned int dst_len = 0;

	oauth2_debug(log, "enter");

	if ((cfg == NULL) || (request == NULL) || (response == NULL))
		goto end;

	if (_oauth2_openidc_provider_resolve(log, cfg, request, NULL,
					     &provider) == false)
		goto end;

	oauth2_nv_list_add(log, params, OAUTH2_RESPONSE_TYPE,
			   OAUTH2_RESPONSE_TYPE_CODE);

	client_id = oauth2_openidc_client_client_id_get(log, cfg->client);
	if (client_id)
		oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID, client_id);

	// redirect_uri = oauth2_openidc_cfg_redirect_uri_get_iss(log, cfg,
	// request, provider);
	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, cfg, request);
	if (redirect_uri)
		oauth2_nv_list_add(log, params, OAUTH2_REDIRECT_URI,
				   redirect_uri);

	scope = oauth2_openidc_client_scope_get(log, cfg->client);
	if (scope)
		oauth2_nv_list_add(log, params, OAUTH2_SCOPE, scope);

	nonce = oauth2_rand_str(log, OAUTH2_NONCE_LENGTH);
	oauth2_nv_list_add(log, params, OAUTH2_NONCE, nonce);

	state = oauth2_rand_str(log, OAUTH2_STATE_LENGTH);
	oauth2_nv_list_add(log, params, OAUTH2_STATE, state);

	pkce = oauth2_rand_str(log, OAUTH2_PKCE_LENGTH);
	oauth2_jose_hash_bytes(log, "sha256", (const unsigned char *)pkce,
			       strlen(pkce), &dst, &dst_len);
	oauth2_base64url_encode(log, dst, dst_len, &code_challenge);
	oauth2_nv_list_add(log, params, OAUTH2_CODE_CHALLENGE, code_challenge);
	oauth2_nv_list_add(log, params, OAUTH2_CODE_CHALLENGE_METHOD, "S256");

	// TODO: handle POST binding as well

	if (*response == NULL)
		goto end;

	if (_oauth2_openidc_state_cookie_set(log, cfg, provider, request,
					     *response, state, pkce) == false)
		goto end;

	location = oauth2_http_url_query_encode(
	    log, provider->authorization_endpoint, params);

	if (oauth2_http_response_header_set(
		log, *response, OAUTH2_HTTP_HDR_LOCATION, location) == false)
		goto end;

	rc = oauth2_http_response_status_code_set(log, *response, 302);

end:

	if (provider)
		oauth2_openidc_provider_free(log, provider);
	if (redirect_uri)
		oauth2_mem_free(redirect_uri);
	if (nonce)
		oauth2_mem_free(nonce);
	if (state)
		oauth2_mem_free(state);
	if (location)
		oauth2_mem_free(location);
	if (params)
		oauth2_nv_list_free(log, params);
	if (code_challenge)
		oauth2_mem_free(code_challenge);
	if (pkce)
		oauth2_mem_free(pkce);
	if (dst)
		oauth2_mem_free(dst);

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

static bool _oauth2_openidc_unauthenticated_request(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    const oauth2_http_request_t *request, oauth2_session_rec_t *session,
    oauth2_http_response_t **response)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	if (response == NULL)
		goto end;
	*response = oauth2_http_response_init(log);

	switch (oauth2_cfg_openidc_unauth_action_get(log, cfg)) {
	case OAUTH2_UNAUTH_ACTION_PASS:
		// r->user = "";
		// oidc_scrub_headers(r);
		goto end;
		break;
	case OAUTH2_UNAUTH_ACTION_HTTP_401:
		oauth2_http_response_status_code_set(log, *response, 401);
		rc = true;
		goto end;
		break;
	case OAUTH2_UNAUTH_ACTION_HTTP_410:
		oauth2_http_response_status_code_set(log, *response, 410);
		rc = true;
		goto end;
		break;
	case OAUTH2_UNAUTH_ACTION_AUTHENTICATE:
	case OAUTH2_UNAUTH_ACTION_UNDEFINED:
	default:
		if (oauth2_http_request_is_xml_http_request(log, request)) {
			oauth2_http_response_status_code_set(log, *response,
							     410);
			rc = true;
			goto end;
		}
		break;
	}

	rc = _oauth2_openidc_authenticate(log, cfg, request, response);

end:

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

static bool _oauth2_openidc_existing_session(oauth2_log_t *log,
					     const oauth2_cfg_openidc_t *c,
					     const oauth2_http_request_t *r,
					     oauth2_session_rec_t *session,
					     oauth2_http_response_t **response,
					     json_t **claims)
{
	bool rc = false;
	json_t *id_token_claims = NULL, *userinfo_claims = NULL;
	const char *key = NULL;
	json_t *value = NULL;

	oauth2_debug(log, "enter");

	*response = oauth2_http_response_init(log);

	if (oauth2_session_handle(log, c->session, r, *response, session) ==
	    false)
		goto end;

	id_token_claims = oauth2_session_rec_id_token_claims_get(log, session);
	userinfo_claims = oauth2_session_rec_userinfo_claims_get(log, session);

	*claims = json_object();
	if (id_token_claims) {
		json_object_foreach(id_token_claims, key, value)
		    json_object_set_new(*claims, key, json_deep_copy(value));
	}
	if (userinfo_claims) {
		json_object_foreach(userinfo_claims, key, value)
		    json_object_set_new(*claims, key, json_deep_copy(value));
	}

	rc = true;

end:

	oauth2_debug(log, "return: %d (%p, %p)", rc, *response, *claims);

	return rc;
}

static bool _oauth2_openidc_id_token_verify(oauth2_log_t *log,
					    oauth2_openidc_provider_t *provider,
					    const char *s_id_token,
					    json_t **id_token, bool ssl_verify)
{
	bool rc = false;
	char *rv = NULL;
	char *options = NULL;

	oauth2_cfg_token_verify_t *verify = NULL;
	if (ssl_verify == false)
		options =
		    oauth2_stradd(NULL, "jwks_uri.ssl_verify", "=", "false");
	rv = oauth2_cfg_token_verify_add_options(log, &verify, "jwks_uri",
						 provider->jwks_uri, options);
	if (rv != NULL) {
		oauth2_error(
		    log, "oauth2_cfg_token_verify_add_options failed: %s", rv);
		goto end;
	}
	if (oauth2_token_verify(log, NULL, verify, s_id_token, id_token) ==
	    false) {
		oauth2_error(log, "id_token verification failed");
		goto end;
	}

	rc = true;

end:

	if (rv)
		oauth2_mem_free(rv);
	if (options)
		oauth2_mem_free(options);
	if (verify)
		oauth2_cfg_token_verify_free(log, verify);

	return rc;
}

static bool
_oauth2_openidc_token_endpoint_call(oauth2_log_t *log,
				    oauth2_openidc_client_t *client,
				    oauth2_openidc_provider_t *provider,
				    oauth2_nv_list_t *params, json_t **json)
{
	bool rc = false;
	oauth2_http_call_ctx_t *http_ctx = NULL;
	char *s_response = NULL;
	oauth2_uint_t status_code = 0;

	oauth2_debug(log, "enter");

	http_ctx = oauth2_http_call_ctx_init(log);
	if (http_ctx == NULL)
		goto end;

	if (oauth2_http_call_ctx_ssl_verify_set(
		log, http_ctx,
		oauth2_openidc_client_ssl_verify_get(log, client)) == false)
		goto end;
	if (oauth2_http_call_ctx_timeout_set(
		log, http_ctx,
		oauth2_openidc_client_http_timeout_get(log, client)) == false)
		goto end;

	// TODO: add configurable extra POST params

	if (oauth2_http_ctx_auth_add(
		log, http_ctx,
		oauth2_openidc_client_token_endpoint_auth_get(log, client),
		params) == false)
		goto end;

	if (oauth2_http_post_form(
		log, oauth2_openidc_provider_token_endpoint_get(log, provider),
		params, http_ctx, &s_response, &status_code) == false)
		goto end;

	if ((status_code < 200) || (status_code >= 300)) {
		rc = false;
		goto end;
	}

	if (oauth2_json_decode_check_error(log, s_response, json) == false)
		goto end;

	rc = true;

end:

	if (s_response)
		oauth2_mem_free(s_response);
	if (http_ctx)
		oauth2_http_call_ctx_free(log, http_ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _oauth2_openidc_token_request(oauth2_log_t *log,
					  const oauth2_cfg_openidc_t *cfg,
					  oauth2_http_request_t *request,
					  oauth2_openidc_provider_t *provider,
					  const char *code, const char *pkce,
					  char **s_id_token,
					  char **s_access_token)
{
	bool rc = false;
	oauth2_nv_list_t *params = NULL;
	char *redirect_uri = NULL;
	json_t *json = NULL;

	oauth2_debug(log, "enter");

	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, cfg, request);
	if (redirect_uri == NULL)
		goto end;

	params = oauth2_nv_list_init(log);
	if (params == NULL)
		goto end;

	oauth2_nv_list_add(log, params, OAUTH2_GRANT_TYPE,
			   OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
	oauth2_nv_list_add(log, params, OAUTH2_CODE, code);
	oauth2_nv_list_add(log, params, OAUTH2_REDIRECT_URI, redirect_uri);
	oauth2_nv_list_add(log, params, OAUTH2_CODE_VERIFIER, pkce);

	if (_oauth2_openidc_token_endpoint_call(log, cfg->client, provider,
						params, &json) == false)
		goto end;

	if (oauth2_json_string_get(log, json, OAUTH2_OPENIDC_ID_TOKEN,
				   s_id_token, NULL) == false) {
		oauth2_error(log, "no %s found in token response",
			     OAUTH2_OPENIDC_ID_TOKEN);
		goto end;
	}

	if (oauth2_json_string_get(log, json, OAUTH2_OPENIDC_ACCESS_TOKEN,
				   s_access_token, NULL) == false) {
		oauth2_error(log, "no %s found in token response",
			     OAUTH2_OPENIDC_ACCESS_TOKEN);
		goto end;
	}

	rc = true;

end:

	if (redirect_uri)
		oauth2_mem_free(redirect_uri);
	if (params)
		oauth2_nv_list_free(log, params);
	if (json)
		json_decref(json);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _oauth2_openidc_userinfo_request(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    oauth2_http_request_t *request, oauth2_openidc_provider_t *provider,
    const char *s_access_token, json_t **userinfo_claims)
{
	bool rc = false;
	oauth2_http_call_ctx_t *http_ctx = NULL;
	char *s_response = NULL;
	oauth2_uint_t status_code = 0;

	if (oauth2_openidc_provider_userinfo_endpoint_get(log, provider) ==
	    NULL) {
		rc = true;
		goto end;
	}

	http_ctx = oauth2_http_call_ctx_init(log);
	if (http_ctx == NULL)
		goto end;

	if (oauth2_http_call_ctx_ssl_verify_set(
		log, http_ctx,
		oauth2_openidc_client_ssl_verify_get(log, cfg->client)) ==
	    false)
		goto end;
	if (oauth2_http_call_ctx_timeout_set(
		log, http_ctx,
		oauth2_openidc_client_http_timeout_get(log, cfg->client)) ==
	    false)
		goto end;

	if (oauth2_http_call_ctx_bearer_token_set(log, http_ctx,
						  s_access_token) == false)
		goto end;

	if (oauth2_http_get(
		log,
		oauth2_openidc_provider_userinfo_endpoint_get(log, provider),
		NULL, http_ctx, &s_response, &status_code) == false)
		goto end;

	if ((status_code < 200) || (status_code >= 300)) {
		rc = false;
		goto end;
	}

	if (oauth2_json_decode_check_error(log, s_response, userinfo_claims) ==
	    false)
		goto end;

	rc = true;

end:

	if (s_response)
		oauth2_mem_free(s_response);
	if (http_ctx)
		oauth2_http_call_ctx_free(log, http_ctx);

	return rc;
}

static bool _oauth2_openidc_redirect_uri_handler(
    oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
    oauth2_http_request_t *request, oauth2_session_rec_t *session,
    oauth2_http_response_t **response)
{
	bool rc = false;
	oauth2_openidc_provider_t *provider = NULL;
	const char *code = NULL, *state = NULL;
	char *location = NULL, *s_id_token = NULL, *s_access_token = NULL,
	     *pkce = NULL;
	json_t *id_token = NULL, *userinfo_claims = NULL;
	oauth2_openidc_proto_state_t *proto_state = NULL;

	oauth2_debug(log, "enter");

	// at this point we know there's a request to the redirect uri
	// errors set in the HTTP response

	code = oauth2_http_request_query_param_get(log, request, OAUTH2_CODE);
	if (code == NULL) {
		oauth2_error(log,
			     "invalid request to the redirect_uri: %s "
			     "parameter could not be found [%s]",
			     OAUTH2_CODE,
			     oauth2_http_request_query_get(log, request));
		goto end;
	}

	state = oauth2_http_request_query_param_get(log, request, OAUTH2_STATE);
	if (state == NULL) {
		oauth2_error(log,
			     "invalid request to the redirect_uri: %s "
			     "parameter could not be found [%s]",
			     OAUTH2_STATE,
			     oauth2_http_request_query_get(log, request));
		goto end;
	}

	*response = oauth2_http_response_init(log);

	if (_oauth2_openidc_state_cookie_get(log, cfg, request, *response,
					     state, &proto_state) == false)
		goto end;
	if (_oauth2_openidc_state_validate(log, cfg, request, proto_state,
					   &provider) == false)
		goto end;

	if (oauth2_openidc_proto_state_pkce_get(log, proto_state, &pkce) ==
	    false)
		goto end;

	if (_oauth2_openidc_token_request(log, cfg, request, provider, code,
					  pkce, &s_id_token,
					  &s_access_token) == false)
		goto end;

	if (_oauth2_openidc_id_token_verify(
		log, provider, s_id_token, &id_token,
		oauth2_openidc_client_ssl_verify_get(log, cfg->client)) ==
	    false)
		goto end;

	if (_oauth2_openidc_userinfo_request(log, cfg, request, provider,
					     s_access_token,
					     &userinfo_claims) == false)
		goto end;

	// TODO: evaluate and set configurable r->user claim
	oauth2_session_rec_user_set(
	    log, session, json_string_value(json_object_get(id_token, "sub")));
	oauth2_session_rec_id_token_claims_set(log, session, id_token);
	oauth2_session_rec_userinfo_claims_set(log, session, userinfo_claims);

	oauth2_session_save(log, cfg->session, request, *response, session);

	// redirect to where we wanted to go originally
	if (oauth2_openidc_proto_state_target_link_uri_get(log, proto_state,
							   &location) == false)
		goto end;

	if (oauth2_http_response_header_set(
		log, *response, OAUTH2_HTTP_HDR_LOCATION, location) == false)
		goto end;
	if (oauth2_http_response_status_code_set(log, *response, 302) == false)
		goto end;

	rc = true;

end:

	if (pkce)
		oauth2_mem_free(pkce);
	if (s_id_token)
		oauth2_mem_free(s_id_token);
	if (s_access_token)
		oauth2_mem_free(s_access_token);
	if (location)
		oauth2_mem_free(location);
	if (proto_state)
		oauth2_openidc_proto_state_free(log, proto_state);
	if (provider)
		oauth2_openidc_provider_free(log, provider);
	if (id_token)
		json_decref(id_token);
	if (userinfo_claims)
		json_decref(userinfo_claims);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_openidc_is_request_to_redirect_uri(oauth2_log_t *log,
					       const oauth2_cfg_openidc_t *cfg,
					       oauth2_http_request_t *request)
{
	bool rc = false;
	char *redirect_uri = NULL, *request_url;

	request_url = oauth2_http_request_url_path_get(log, request);
	if (request_url == NULL)
		goto end;

	// redirect_uri = oauth2_openidc_cfg_redirect_uri_get_iss(log, cfg,
	// request, provider);
	redirect_uri = oauth2_cfg_openidc_redirect_uri_get(log, cfg, request);
	if (redirect_uri == NULL)
		goto end;

	oauth2_debug(log, "comparing: \"%s\"=\"%s\"", request_url,
		     redirect_uri);

	if (strcmp(redirect_uri, request_url) != 0)
		goto end;

	rc = true;

end:

	if (request_url)
		oauth2_mem_free(request_url);
	if (redirect_uri)
		oauth2_mem_free(redirect_uri);

	return rc;
}

static bool _oauth2_openidc_internal_requests(oauth2_log_t *log,
					      const oauth2_cfg_openidc_t *cfg,
					      oauth2_http_request_t *request,
					      oauth2_session_rec_t *session,
					      oauth2_http_response_t **response,
					      bool *processed)
{
	bool rc = true;

	oauth2_debug(log, "enter");

	if (oauth2_openidc_is_request_to_redirect_uri(log, cfg, request) ==
	    true) {
		rc = _oauth2_openidc_redirect_uri_handler(log, cfg, request,
							  session, response);
		*processed = true;
		goto end;
	}

	// TODO:
	// - session info
	// - key materials
	// - 3rd-party init SSO

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

bool oauth2_openidc_handle(oauth2_log_t *log, const oauth2_cfg_openidc_t *cfg,
			   oauth2_http_request_t *request,
			   oauth2_http_response_t **response, json_t **claims)
{
	bool rc = false, processed = false;
	oauth2_session_rec_t *session = NULL;

	oauth2_debug(log, "incoming request: %s%s%s",
		     oauth2_http_request_path_get(log, request),
		     oauth2_http_request_query_get(log, request) ? "?" : "",
		     oauth2_http_request_query_get(log, request)
			 ? oauth2_http_request_query_get(log, request)
			 : "");

	if (oauth2_session_load(log, cfg->session, request, &session) == false)
		goto end;

	rc = _oauth2_openidc_internal_requests(log, cfg, request, session,
					       response, &processed);
	if ((processed == true) || (rc == false))
		goto end;

	if (oauth2_session_rec_user_get(log, session) != NULL) {
		oauth2_debug(log, "user found in session: %s",
			     oauth2_session_rec_user_get(log, session));
		rc = _oauth2_openidc_existing_session(
		    log, cfg, request, session, response, claims);
		goto end;
	}

	oauth2_debug(log, "no user found in session");

	rc = _oauth2_openidc_unauthenticated_request(log, cfg, request, session,
						     response);

end:

	oauth2_session_rec_free(log, session);

	oauth2_debug(log, "return: %d", rc);

	return rc;
}
