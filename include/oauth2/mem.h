#ifndef _OAUTH2_MEM_H_
#define _OAUTH2_MEM_H_

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
