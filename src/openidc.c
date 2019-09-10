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

#include "oauth2/log.h"
#include "oauth2/mem.h"

#include "oauth2/openidc.h"
#include "oauth2/session.h"

#include "util_int.h"

#include <string.h>

// TODO: set add log
typedef struct oauth2_openidc_cfg_t {
	char *redirect_uri;
	oauth2_openidc_provider_resolver_t *provider_resolver;
	oauth2_unauth_action_t unauth_action;
} oauth2_openidc_cfg_t;

oauth2_openidc_cfg_t *oauth2_openidc_cfg_init(oauth2_log_t *log)
{
	oauth2_openidc_cfg_t *c = NULL;

	c = oauth2_mem_alloc(sizeof(oauth2_openidc_cfg_t));
	if (c == NULL)
		goto end;

	// TODO: memset all of it?
	c->redirect_uri = NULL;

end:

	return c;
}

void oauth2_openidc_cfg_free(oauth2_log_t *log, oauth2_openidc_cfg_t *c)
{
	if (c == NULL)
		goto end;

	if (c->redirect_uri)
		oauth2_mem_free(c->redirect_uri);

	oauth2_mem_free(c);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET(openidc, cfg, redirect_uri, char *, str)

bool oauth2_openidc_cfg_provider_resolver_set(
    oauth2_log_t *log, oauth2_openidc_cfg_t *cfg,
    oauth2_openidc_provider_resolver_t *resolver)
{
	cfg->provider_resolver = resolver;
	return true;
}

oauth2_openidc_provider_resolver_t *
oauth2_openidc_cfg_provider_resolver_get(oauth2_log_t *log,
					 const oauth2_openidc_cfg_t *cfg)
{
	return cfg->provider_resolver;
}

char *oauth2_openidc_cfg_redirect_uri_get(oauth2_log_t *log,
					  const oauth2_openidc_cfg_t *c,
					  const oauth2_http_request_t *r)
{

	char *redirect_uri = NULL;

	if ((c == NULL) || (c->redirect_uri == NULL))
		goto end;

	// absolute redirect uri
	if (c->redirect_uri[0] != _OAUTH2_CHAR_FSLASH) {
		redirect_uri = oauth2_strdup(c->redirect_uri);
		goto end;
	}

	// relative redirect uri
	redirect_uri = oauth2_http_request_url_base_get(log, r);
	if (redirect_uri == NULL)
		goto end;

	redirect_uri = oauth2_stradd(redirect_uri, c->redirect_uri, NULL, NULL);

	oauth2_debug(log, "derived absolute redirect uri: %s", redirect_uri);

end:

	return redirect_uri;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, cfg, unauth_action,
				      oauth2_unauth_action_t, uint)

typedef struct oauth2_openidc_provider_t {
	char *issuer;
	char *authorization_endpoint;
	char *scope;
	char *client_id;
	char *client_secret;
} oauth2_openidc_provider_t;

oauth2_openidc_provider_t *oauth2_openidc_provider_init(oauth2_log_t *log)
{
	oauth2_openidc_provider_t *p = NULL;

	p = oauth2_mem_alloc(sizeof(oauth2_openidc_provider_t));
	if (p == NULL)
		goto end;

	p->issuer = NULL;
	p->authorization_endpoint = NULL;
	p->scope = NULL;
	p->client_id = NULL;
	p->client_secret = NULL;

end:

	return p;
}

void oauth2_openidc_provider_free(oauth2_log_t *log,
				  oauth2_openidc_provider_t *p)
{
	if (p == NULL)
		goto end;

	if (p->issuer)
		oauth2_mem_free(p->issuer);
	if (p->client_id)
		oauth2_mem_free(p->client_id);

	oauth2_mem_free(p);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, issuer, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, authorization_endpoint,
				      char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, scope, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, client_id, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, client_secret, char *,
				      str)

char *oauth2_openidc_cfg_redirect_uri_get_iss(
    oauth2_log_t *log, const oauth2_openidc_cfg_t *c,
    const oauth2_http_request_t *r, const oauth2_openidc_provider_t *provider)
{
	char *redirect_uri = NULL, *issuer = NULL, *sep = NULL;

	redirect_uri = oauth2_openidc_cfg_redirect_uri_get(log, c, r);
	if (redirect_uri == NULL)
		goto end;

	// if (provider->issuer_specific_redirect_uri != 0) {

	if (provider->issuer)
		issuer = oauth2_url_encode(log, provider->issuer);

	if (issuer == NULL)
		goto end;

	sep = strchr(redirect_uri, _OAUTH2_CHAR_QUERY) != NULL
		  ? _OAUTH2_STR_AMP
		  : _OAUTH2_STR_QMARK;
	redirect_uri = _oauth2_stradd4(redirect_uri, sep, "iss",
				       _OAUTH2_STR_EQUAL, issuer);

end:
	if (issuer)
		oauth2_mem_free(issuer);

	return redirect_uri;
}

static bool _oauth2_openidc_authenticate(oauth2_log_t *log,
					 const oauth2_openidc_cfg_t *cfg,
					 const oauth2_http_request_t *request,
					 oauth2_session_rec_t *session,
					 oauth2_http_response_t **response)
{
	bool rc = false;
	oauth2_openidc_provider_t *provider = NULL;
	char *nonce = NULL, *state = NULL, *location = NULL;
	oauth2_nv_list_t *params = oauth2_nv_list_init(log);

	oauth2_debug(log, "enter");

	if (response == NULL)
		goto end;

	if ((cfg->provider_resolver(log, request, &provider) == false) ||
	    (provider == NULL))
		goto end;

	oauth2_nv_list_add(log, params, OAUTH2_RESPONSE_TYPE,
			   OAUTH2_RESPONSE_TYPE_CODE);

	if (provider->client_id)
		oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID,
				   provider->client_id);
	if (cfg->redirect_uri)
		oauth2_nv_list_add(log, params, OAUTH2_REDIRECT_URI,
				   cfg->redirect_uri);

	if (provider->scope)
		oauth2_nv_list_add(log, params, OAUTH2_SCOPE, provider->scope);

	nonce = oauth2_rand_str(log, 10);
	oauth2_nv_list_add(log, params, OAUTH2_NONCE, nonce);

	state = oauth2_rand_str(log, 10);
	oauth2_nv_list_add(log, params, OAUTH2_STATE, state);

	// TODO: set state cookie
	// TODO: handle POST binding as well

	*response = oauth2_http_response_init(log);
	if (*response == NULL)
		goto end;

	location = oauth2_http_url_query_encode(
	    log, provider->authorization_endpoint, params);

	rc = oauth2_http_response_header_set(
	    log, *response, OAUTH2_HTTP_HDR_LOCATION, location);
	if (rc == false)
		goto end;

	rc = oauth2_http_response_status_code_set(log, *response, 302);

end:

	if (nonce)
		oauth2_mem_free(nonce);
	if (state)
		oauth2_mem_free(state);
	if (location)
		oauth2_mem_free(location);
	if (params)
		oauth2_nv_list_free(log, params);

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

static bool _oauth2_openidc_unauthenticated_request(
    oauth2_log_t *log, const oauth2_openidc_cfg_t *cfg,
    const oauth2_http_request_t *request, oauth2_session_rec_t *session,
    oauth2_http_response_t **response)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	if (response == NULL)
		goto end;
	*response = oauth2_http_response_init(log);

	switch (oauth2_openidc_cfg_unauth_action_get(log, cfg)) {
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
		if (oauth2_http_is_xml_http_request(log, request)) {
			oauth2_http_response_status_code_set(log, *response,
							     410);
			rc = true;
			goto end;
		}
		break;
	}

	rc = _oauth2_openidc_authenticate(log, cfg, request, session, response);

end:

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

static bool _oauth2_openidc_existing_session(oauth2_log_t *log,
					     const oauth2_openidc_cfg_t *c,
					     const oauth2_http_request_t *r,
					     oauth2_session_rec_t *session,
					     oauth2_http_response_t **response)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	goto end;

end:

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

bool oauth2_openidc_handle(oauth2_log_t *log, const oauth2_openidc_cfg_t *c,
			   const oauth2_http_request_t *r,
			   oauth2_http_response_t **response)
{
	bool rc = false;
	oauth2_session_rec_t *session = NULL;

	oauth2_debug(log, "incoming request: %s%s%s",
		     oauth2_http_request_path_get(log, r),
		     oauth2_http_request_path_get(log, r) ? "?" : "",
		     oauth2_http_request_path_get(log, r)
			 ? oauth2_http_request_path_get(log, r)
			 : "");

	if (oauth2_session_load(log, c, r, &session) == false)
		goto end;

	// TODO: handle requests to the redirect uri
	// TODO: handle other custom request handlers:
	// - session info
	// - key materials
	// - 3rd-party init SSO

	if (oauth2_session_rec_user_get(log, session) != NULL) {
		rc = _oauth2_openidc_existing_session(log, c, r, session,
						      response);
		goto end;
	}

	rc = _oauth2_openidc_unauthenticated_request(log, c, r, session,
						     response);

end:

	oauth2_session_rec_free(log, session);

	oauth2_debug(log, "return: %d", rc);

	return rc;
}
