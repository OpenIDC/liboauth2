/***************************************************************************
 *
 * Copyright (C) 2018-2025 - ZmartZone Holding BV
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

#include "oauth2/mem.h"
#include "cjose/util.h"
#include "oauth2/util.h"
#include "util_int.h"
#include <stdlib.h>
#include <string.h>

#include "curl/curl.h"

static void *oauth2_mem_calloc_callback(size_t nmemb, size_t size)
{
	return oauth2_mem_alloc(nmemb * size);
}

void oauth2_mem_set_alloc_funcs(oauth2_mem_alloc_fn_t alloc,
				oauth2_mem_realloc_fn_t realloc,
				oauth2_mem_dealloc_fn_t dealloc)
{
	cjose_set_alloc_funcs(alloc, realloc, dealloc);
	curl_global_init_mem(CURL_GLOBAL_ALL, alloc, dealloc, realloc,
			     oauth2_strdup, oauth2_mem_calloc_callback);
}

void oauth2_mem_set_alloc_ex_funcs(oauth2_mem_alloc3_fn_t alloc3,
				   oauth2_mem_realloc3_fn_t realloc3,
				   oauth2_mem_dealloc3_fn_t dealloc3)
{
	cjose_set_alloc_ex_funcs(alloc3, realloc3, dealloc3);
	curl_global_init_mem(CURL_GLOBAL_ALL, cjose_get_alloc(),
			     cjose_get_dealloc(), cjose_get_realloc(),
			     oauth2_strdup, oauth2_mem_calloc_callback);
}

oauth2_mem_alloc_fn_t oauth2_mem_get_alloc()
{
	return cjose_get_alloc();
}

oauth2_mem_alloc3_fn_t oauth2_mem_get_alloc3()
{
	return cjose_get_alloc3();
}

oauth2_mem_realloc_fn_t oauth2_mem_get_realloc()
{
	return cjose_get_realloc();
}

oauth2_mem_realloc3_fn_t oauth2_mem_get_realloc3()
{
	return cjose_get_realloc3();
}

oauth2_mem_dealloc_fn_t oauth2_mem_get_dealloc()
{
	return cjose_get_dealloc();
}

oauth2_mem_dealloc3_fn_t oauth2_mem_get_dealloc3()
{
	return cjose_get_dealloc3();
}

void *oauth2_mem_alloc(size_t size)
{
	void *ptr = oauth2_mem_get_alloc()(size);
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

void oauth2_mem_free(void *ptr)
{
	oauth2_mem_get_dealloc()(ptr);
}
