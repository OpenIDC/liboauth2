#ifndef _OAUTH2_MEM_H_
#define _OAUTH2_MEM_H_

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

/**
 * @file mem.h
 * @brief Overridable memory allocation.
 *
 * All memory the library allocates goes through a single, replaceable
 * set of allocator functions, shared with cjose and libcurl: by
 * default the C library's malloc/realloc/free, or whatever a server
 * binding installs instead (e.g. to account allocations to a server
 * pool or to instrument them). Consequently every string, buffer or
 * object the API hands out must be released with oauth2_mem_free(),
 * and never with free(), and any memory a caller passes ownership of
 * to the library must have been obtained from oauth2_mem_alloc().
 */

#include <stddef.h>

/**
 * @name Allocator functions
 * The basic allocator interface, with the signatures of malloc(),
 * realloc() and free(); the getters return the functions currently in
 * effect.
 * @{
 */
/** @brief Allocate a block of the given size, as malloc(). */
typedef void *(*oauth2_mem_alloc_fn_t)(size_t);
/** @brief Resize a block, as realloc(). */
typedef void *(*oauth2_mem_realloc_fn_t)(void *, size_t);
/** @brief Release a block, as free(). */
typedef void (*oauth2_mem_dealloc_fn_t)(void *);

/** @brief The allocation function currently in effect. */
oauth2_mem_alloc_fn_t oauth2_mem_get_alloc();
/** @brief The reallocation function currently in effect. */
oauth2_mem_realloc_fn_t oauth2_mem_get_realloc();
/** @brief The deallocation function currently in effect. */
oauth2_mem_dealloc_fn_t oauth2_mem_get_dealloc();

/**
 * @brief Install a custom allocator.
 *
 * Call before oauth2_init() (util.h) and before any allocation is
 * made: the functions are installed into cjose and, through
 * curl_global_init_mem(), into libcurl, so memory allocated earlier
 * would be released through the wrong function.
 *
 * @param alloc   the allocation function
 * @param realloc the reallocation function
 * @param dealloc the deallocation function
 */
void oauth2_mem_set_alloc_funcs(oauth2_mem_alloc_fn_t alloc,
				oauth2_mem_realloc_fn_t realloc,
				oauth2_mem_dealloc_fn_t dealloc);
/** @} */

/**
 * @name Extended allocator functions
 * The same interface with the source file name and line number of the
 * allocation site as extra arguments, for allocators that track where
 * memory is allocated (e.g. a debugging allocator or a server pool
 * API that records the caller). Installing extended functions with
 * oauth2_mem_set_alloc_ex_funcs() also installs plain wrappers around
 * them, so oauth2_mem_get_alloc() etc. keep working, and vice versa.
 * @{
 */
/** @brief Allocate a block, given the caller's file and line. */
typedef void *(*oauth2_mem_alloc3_fn_t)(size_t, const char *, int);
/** @brief Resize a block, given the caller's file and line. */
typedef void *(*oauth2_mem_realloc3_fn_t)(void *, size_t, const char *, int);
/** @brief Release a block, given the caller's file and line. */
typedef void (*oauth2_mem_dealloc3_fn_t)(void *, const char *, int);

/** @brief The extended allocation function currently in effect. */
oauth2_mem_alloc3_fn_t oauth2_mem_get_alloc3();
/** @brief The extended reallocation function currently in effect. */
oauth2_mem_realloc3_fn_t oauth2_mem_get_realloc3();
/** @brief The extended deallocation function currently in effect. */
oauth2_mem_dealloc3_fn_t oauth2_mem_get_dealloc3();

/**
 * @brief Install a custom allocator that receives the allocation
 *        site.
 *
 * As oauth2_mem_set_alloc_funcs(), to be called before anything is
 * allocated; libcurl, which has no such interface, is set up with the
 * plain wrappers.
 *
 * @param alloc3   the allocation function
 * @param realloc3 the reallocation function
 * @param dealloc3 the deallocation function
 */
void oauth2_mem_set_alloc_ex_funcs(oauth2_mem_alloc3_fn_t alloc3,
				   oauth2_mem_realloc3_fn_t realloc3,
				   oauth2_mem_dealloc3_fn_t dealloc3);
/** @} */

/**
 * @name Allocation
 * @{
 */

/**
 * @brief Allocate a zero-initialized block through the installed
 *        allocator.
 *
 * @return the block, or NULL when the allocator returns NULL
 */
void *oauth2_mem_alloc(size_t);

/**
 * @brief Release memory obtained from oauth2_mem_alloc() or returned
 *        by any library function.
 *
 * Whether a NULL pointer is accepted depends on the installed
 * deallocation function; the default one (free()) ignores it.
 */
void oauth2_mem_free(void *);
/** @} */

#endif /* _OAUTH2_MEM_H_ */
