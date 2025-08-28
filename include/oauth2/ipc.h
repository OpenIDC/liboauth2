#ifndef _OAUTH2_IPC_H_
#define _OAUTH2_IPC_H_

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

#include <semaphore.h>
#include <stdbool.h>

#include "oauth2/util.h"

// TODO: macro for post_config and child_init functions

OAUTH2_TYPE_DECLARE(ipc, mutex)
bool oauth2_ipc_mutex_post_config(oauth2_log_t *log, oauth2_ipc_mutex_t *m);
bool oauth2_ipc_mutex_lock(oauth2_log_t *log, oauth2_ipc_mutex_t *m);
bool oauth2_ipc_mutex_unlock(oauth2_log_t *log, oauth2_ipc_mutex_t *m);

OAUTH2_TYPE_DECLARE(ipc, thread_mutex)
bool oauth2_ipc_thread_mutex_lock(oauth2_log_t *log,
				  oauth2_ipc_thread_mutex_t *m);
bool oauth2_ipc_thread_mutex_unlock(oauth2_log_t *log,
				    oauth2_ipc_thread_mutex_t *m);

OAUTH2_TYPE_DECLARE(ipc, sema)
bool oauth2_ipc_sema_post_config(oauth2_log_t *log, oauth2_ipc_sema_t *sema);
bool oauth2_ipc_sema_post(oauth2_log_t *log, oauth2_ipc_sema_t *sema);
bool oauth2_ipc_sema_wait(oauth2_log_t *log, oauth2_ipc_sema_t *sema);
bool oauth2_ipc_sema_trywait(oauth2_log_t *log, oauth2_ipc_sema_t *sema);

typedef struct oauth2_ipc_shm_t oauth2_ipc_shm_t;
oauth2_ipc_shm_t *oauth2_ipc_shm_init(oauth2_log_t *log, size_t size);
void oauth2_ipc_shm_free(oauth2_log_t *, oauth2_ipc_shm_t *);
bool oauth2_ipc_shm_post_config(oauth2_log_t *log, oauth2_ipc_shm_t *shm);
bool oauth2_ipc_shm_child_init(oauth2_log_t *log, oauth2_ipc_shm_t *shm);
void *oauth2_ipc_shm_get(oauth2_log_t *log, oauth2_ipc_shm_t *s);

#endif /* _OAUTH2_IPC_H_ */
