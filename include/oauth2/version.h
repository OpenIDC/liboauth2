#ifndef _OAUTH2_VERSION_H_
#define _OAUTH2_VERSION_H_

/* include/oauth2/version.h  Generated from version.h.in by autoheader.  */

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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#define OAUTH2_PACKAGE_NAME          "@PACKAGE_NAME@"
#define OAUTH2_PACKAGE_VERSION       "@PACKAGE_VERSION@"

const char *oauth2_version();
const char *oauth2_package_string();

#endif  // _OAUTH2_VERSION_H_
