#ifndef _OAUTH2_OPENIDC_H_
#define _OAUTH2_OPENIDC_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone IT BV - www.zmartzone.eu
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

#include "oauth2/http.h"
#include "oauth2/util.h"

/*
 * location-based OpenID Connect configuration
 */

OAUTH2_TYPE_DECLARE(openidc, cfg)
OAUTH2_TYPE_DECLARE_MEMBER_SET(openidc, cfg, redirect_uri, char *)

char *oauth2_openidc_cfg_redirect_uri_get(oauth2_log_t *,
					  const oauth2_openidc_cfg_t *,
					  const oauth2_http_request_t *);

/*
 * OpenID Connect provider configuration
 */

OAUTH2_TYPE_DECLARE(openidc, provider)
OAUTH2_TYPE_DECLARE_MEMBER_SET_GET(openidc, provider, issuer, char *)

char *oauth2_openidc_cfg_redirect_uri_get_iss(
    oauth2_log_t *, const oauth2_openidc_cfg_t *, const oauth2_http_request_t *,
    const oauth2_openidc_provider_t *);

#endif /* _OAUTH2_OPENIDC_H_ */
