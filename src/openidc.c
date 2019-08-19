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

typedef struct oauth2_openidc_provider_t {
	char *issuer;
	char *client_id;
} oauth2_openidc_provider_t;

oauth2_openidc_provider_t *oauth2_openidc_provider_init(oauth2_log_t *log)
{
	oauth2_openidc_provider_t *p = NULL;

	p = oauth2_mem_alloc(sizeof(oauth2_openidc_provider_t));
	if (p == NULL)
		goto end;

	// TODO: memset all of it?
	p->issuer = NULL;
	p->client_id = NULL;

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

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, client_id, char *, str)

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

oauth2_http_status_code_t oauth2_openidc_handle(oauth2_log_t *log,
						const oauth2_openidc_cfg_t *c,
						const oauth2_http_request_t *r)
{

	oauth2_http_status_code_t status_code = 0;
	oauth2_session_rec_t *session = NULL;

	oauth2_debug(log, "incoming request: %s%s%s",
		     oauth2_http_request_path_get(log, r),
		     oauth2_http_request_path_get(log, r) ? "?" : "",
		     oauth2_http_request_path_get(log, r)
			 ? oauth2_http_request_path_get(log, r)
			 : "");

	if (oauth2_session_load(log, c, r, &session) == false)
		goto end;

	// check session->user

end:

	oauth2_session_rec_free(log, session);

	return status_code;
}
