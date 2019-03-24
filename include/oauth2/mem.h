#ifndef _OAUTH2_MEM_H_
#define _OAUTH2_MEM_H_

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

#include <stddef.h>

typedef void *(*oauth2_mem_alloc_fn_t)(size_t);
typedef void *(*oauth2_mem_realloc_fn_t)(void *, size_t);
typedef void (*oauth2_mem_dealloc_fn_t)(void *);

oauth2_mem_alloc_fn_t oauth2_mem_get_alloc();
oauth2_mem_realloc_fn_t oauth2_mem_get_realloc();
oauth2_mem_dealloc_fn_t oauth2_mem_get_dealloc();

void oauth2_mem_set_alloc_funcs(oauth2_mem_alloc_fn_t alloc,
				oauth2_mem_realloc_fn_t realloc,
				oauth2_mem_dealloc_fn_t dealloc);

typedef void *(*oauth2_mem_alloc3_fn_t)(size_t, const char *, int);
typedef void *(*oauth2_mem_realloc3_fn_t)(void *, size_t, const char *, int);
typedef void (*oauth2_mem_dealloc3_fn_t)(void *, const char *, int);

oauth2_mem_alloc3_fn_t oauth2_mem_get_alloc3();
oauth2_mem_realloc3_fn_t oauth2_mem_get_realloc3();
oauth2_mem_dealloc3_fn_t oauth2_mem_get_dealloc3();

void oauth2_mem_set_alloc_ex_funcs(oauth2_mem_alloc3_fn_t alloc3,
				   oauth2_mem_realloc3_fn_t realloc3,
				   oauth2_mem_dealloc3_fn_t dealloc3);

void *oauth2_mem_alloc(size_t);
void oauth2_mem_free(void *);

#endif /* _OAUTH2_MEM_H_ */
