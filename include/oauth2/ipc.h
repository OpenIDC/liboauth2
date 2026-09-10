#ifndef _OAUTH2_IPC_H_
#define _OAUTH2_IPC_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2026 - ZmartZone Holding BV
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
 * @file ipc.h
 * @brief Inter-process synchronization and shared memory.
 *
 * The primitives the cache backends (cache.h) use to coordinate the
 * worker processes of a pre-forking server such as Apache httpd: a
 * process-shared mutex, a process-shared counting semaphore and an
 * anonymous shared memory segment, plus an in-process thread mutex.
 * Their lifecycle follows that of the server: the object is allocated
 * with its _init function while the configuration is read, the
 * underlying OS object is created with its _post_config function in
 * the parent process once the configuration is complete and before
 * the workers are forked - so that the workers inherit it - and the
 * workers then use it; _free releases it. Any function here accepts a
 * NULL object and fails (or does nothing) on it.
 *
 * On POSIX the semaphores are named semaphores that are unlinked right
 * after their creation and the shared memory is an anonymous
 * MAP_SHARED mapping, both inherited across fork(). On Windows, where
 * nothing forks, they are implemented on unnamed kernel semaphores,
 * critical sections and process heap memory and coordinate the threads
 * of a single process.
 */

#include <stdbool.h>

#include "oauth2/util.h"

// TODO: macro for post_config and child_init functions

/**
 * @name Process-shared mutex
 * A binary semaphore in mutex clothing: oauth2_ipc_mutex_init()
 * allocates it, oauth2_ipc_mutex_post_config() creates the underlying
 * semaphore in the unlocked state - call it in the parent before
 * forking - and the workers serialize on it with
 * oauth2_ipc_mutex_lock() and oauth2_ipc_mutex_unlock(). It is not
 * recursive and has no notion of an owner: locking it twice from the
 * same thread deadlocks, and any process or thread can unlock it.
 * The file cache backend serializes its directory operations on one,
 * the shared memory cache backend its access to the segment.
 * @{
 */

/**
 * @brief Opaque process-shared mutex; the _clone function the
 *        declaration macro names is not implemented.
 */
OAUTH2_TYPE_DECLARE(ipc, mutex)

/**
 * @brief Create the underlying semaphore, in the unlocked state.
 *
 * Call once in the parent process, after the configuration has been
 * read and before the workers are forked.
 *
 * @param log the log handle to use
 * @param m   the mutex to create the semaphore for
 * @return true on success, false when the semaphore could not be
 *         created
 */
bool oauth2_ipc_mutex_post_config(oauth2_log_t *log, oauth2_ipc_mutex_t *m);

/**
 * @brief Acquire the mutex, blocking until it is available.
 *
 * @param log the log handle to use
 * @param m   the mutex to acquire
 * @return true when the mutex was acquired, false on error
 */
bool oauth2_ipc_mutex_lock(oauth2_log_t *log, oauth2_ipc_mutex_t *m);

/**
 * @brief Release the mutex.
 *
 * @param log the log handle to use
 * @param m   the mutex to release
 * @return true when the mutex was released, false on error
 */
bool oauth2_ipc_mutex_unlock(oauth2_log_t *log, oauth2_ipc_mutex_t *m);
/** @} */

/**
 * @name Thread mutex
 * An in-process mutex - a pthread mutex, a critical section on Windows
 * - serializing the threads of one process. It is ready for use right
 * after oauth2_ipc_thread_mutex_init(), there is no post_config step,
 * and oauth2_ipc_thread_mutex_free() destroys it. The library
 * serializes its use of the shared libcurl handle on one, the Redis
 * cache backend the use of its connection.
 * @{
 */

/**
 * @brief Opaque thread mutex; the _clone function the declaration
 *        macro names is not implemented.
 */
OAUTH2_TYPE_DECLARE(ipc, thread_mutex)

/**
 * @brief Acquire the mutex, blocking until it is available.
 *
 * @param log the log handle to use
 * @param m   the mutex to acquire
 * @return true when the mutex was acquired, false on error
 */
bool oauth2_ipc_thread_mutex_lock(oauth2_log_t *log,
				  oauth2_ipc_thread_mutex_t *m);

/**
 * @brief Release the mutex.
 *
 * @param log the log handle to use
 * @param m   the mutex to release
 * @return true when the mutex was released, false on error
 */
bool oauth2_ipc_thread_mutex_unlock(oauth2_log_t *log,
				    oauth2_ipc_thread_mutex_t *m);
/** @} */

/**
 * @name Process-shared semaphore
 * A counting semaphore shared with the processes forked after
 * oauth2_ipc_sema_post_config() created it, starting at a count of
 * zero: oauth2_ipc_sema_post() increments it and oauth2_ipc_sema_wait()
 * and oauth2_ipc_sema_trywait() decrement it, the former blocking
 * while the count is zero. The process-shared mutex and the shared
 * memory segment are built on it.
 * @{
 */

/**
 * @brief Opaque process-shared semaphore; the _clone function the
 *        declaration macro names is not implemented.
 */
OAUTH2_TYPE_DECLARE(ipc, sema)

/**
 * @brief Create the underlying semaphore, with a count of zero.
 *
 * Call once in the parent process before the workers are forked. On
 * POSIX the semaphore is created under a name derived from the process
 * id and the address of @p sema and unlinked immediately, so that it
 * lives on only through the handle the workers inherit.
 *
 * @param log  the log handle to use
 * @param sema the semaphore to create
 * @return true on success, false when the semaphore could not be
 *         created
 */
bool oauth2_ipc_sema_post_config(oauth2_log_t *log, oauth2_ipc_sema_t *sema);

/**
 * @brief Increment the semaphore, waking one waiter if there is any.
 *
 * @param log  the log handle to use
 * @param sema the semaphore to increment
 * @return true on success, false when the semaphore has not been
 *         created with oauth2_ipc_sema_post_config() or the increment
 *         failed
 */
bool oauth2_ipc_sema_post(oauth2_log_t *log, oauth2_ipc_sema_t *sema);

/**
 * @brief Decrement the semaphore, blocking while its count is zero.
 *
 * @param log  the log handle to use
 * @param sema the semaphore to decrement
 * @return true when the semaphore was decremented, false on error
 */
bool oauth2_ipc_sema_wait(oauth2_log_t *log, oauth2_ipc_sema_t *sema);

/**
 * @brief Decrement the semaphore if its count is positive, without
 *        blocking.
 *
 * @param log  the log handle to use
 * @param sema the semaphore to decrement
 * @return true when the semaphore was decremented, false when its
 *         count was zero or on error
 */
bool oauth2_ipc_sema_trywait(oauth2_log_t *log, oauth2_ipc_sema_t *sema);
/** @} */

/**
 * @name Shared memory
 * A fixed-size block of memory shared between the parent and the
 * worker processes: oauth2_ipc_shm_init() records the size,
 * oauth2_ipc_shm_post_config() maps the block in the parent - zero-
 * filled, before the workers are forked so that they inherit the
 * mapping - oauth2_ipc_shm_child_init() is called in each worker when
 * it starts and oauth2_ipc_shm_get() returns the address of the block.
 * Access to the contents is not synchronized: pair the segment with a
 * process-shared mutex, as the shared memory cache backend does.
 * @{
 */

/** @brief Opaque shared memory segment. */
typedef struct oauth2_ipc_shm_t oauth2_ipc_shm_t;

/**
 * @brief Allocate a shared memory segment descriptor.
 *
 * @param log  the log handle to use
 * @param size the size of the segment in bytes, mapped by
 *             oauth2_ipc_shm_post_config()
 * @return the new descriptor, to be released with oauth2_ipc_shm_free()
 */
oauth2_ipc_shm_t *oauth2_ipc_shm_init(oauth2_log_t *log, size_t size);

/**
 * @brief Unmap the segment, if mapped, and free its descriptor.
 */
void oauth2_ipc_shm_free(oauth2_log_t *, oauth2_ipc_shm_t *);

/**
 * @brief Map the segment in the parent process.
 *
 * Creates the internal semaphores of the segment and maps the number
 * of bytes passed to oauth2_ipc_shm_init() as zero-filled anonymous
 * shared memory (process heap memory on Windows). Call once, before
 * the workers are forked.
 *
 * @param log the log handle to use
 * @param shm the segment to map
 * @return true on success, false when the semaphores or the mapping
 *         could not be created
 */
bool oauth2_ipc_shm_post_config(oauth2_log_t *log, oauth2_ipc_shm_t *shm);

/**
 * @brief Register a worker process with the segment.
 *
 * Call in each worker when it starts, after it was forked from the
 * parent that mapped the segment.
 *
 * @param log the log handle to use
 * @param shm the segment the worker attaches to
 * @return true on success, false on error
 */
bool oauth2_ipc_shm_child_init(oauth2_log_t *log, oauth2_ipc_shm_t *shm);

/**
 * @brief Get the address of the mapped segment.
 *
 * @param log the log handle to use
 * @param s   the segment
 * @return the address of the block, or NULL before
 *         oauth2_ipc_shm_post_config() mapped it
 */
void *oauth2_ipc_shm_get(oauth2_log_t *log, oauth2_ipc_shm_t *s);
/** @} */

#endif /* _OAUTH2_IPC_H_ */
