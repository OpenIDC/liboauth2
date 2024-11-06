/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
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

#include <oauth2/mem.h>

#include "openidc_int.h"
#include "util_int.h"

oauth2_openidc_provider_t *oauth2_openidc_provider_init(oauth2_log_t *log)
{
	oauth2_openidc_provider_t *p = NULL;

	p = oauth2_mem_alloc(sizeof(oauth2_openidc_provider_t));
	if (p == NULL)
		goto end;

	p->issuer = NULL;
	p->authorization_endpoint = NULL;
	p->token_endpoint = NULL;
	p->userinfo_endpoint = NULL;
	p->jwks_uri = NULL;

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
	if (p->authorization_endpoint)
		oauth2_mem_free(p->authorization_endpoint);
	if (p->token_endpoint)
		oauth2_mem_free(p->token_endpoint);
	if (p->jwks_uri)
		oauth2_mem_free(p->jwks_uri);
	if (p->userinfo_endpoint)
		oauth2_mem_free(p->userinfo_endpoint);

	oauth2_mem_free(p);

end:

	return;
}

_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, issuer, char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, authorization_endpoint,
				      char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, token_endpoint, char *,
				      str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, userinfo_endpoint,
				      char *, str)
_OAUTH2_TYPE_IMPLEMENT_MEMBER_SET_GET(openidc, provider, jwks_uri, char *, str)
