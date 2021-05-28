#ifndef _OAUTH2_IPC_H_
#define _OAUTH2_IPC_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2021 - ZmartZone Holding BV - www.zmartzone.eu
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

#include <semaphore.h>
#include <stdbool.h>

#include "oauth2/util.h"

// TODO: macro for post_config and child_init functions

OAUTH2_TYPE_DECLARE(ipc, mutex)
bool oauth2_ipc_mutex_post_config(oauth2_log_t *log, oauth2_ipc_mutex_t *m);
bool oauth2_ipc_mutex_lock(oauth2_log_t *log, oauth2_ipc_mutex_t *m);
bool oauth2_ipc_mutex_unlock(oauth2_log_t *log, oauth2_ipc_mutex_t *m);

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
