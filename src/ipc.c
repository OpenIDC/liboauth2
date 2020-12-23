/***************************************************************************
 *
 * Copyright (C) 2018-2020 - ZmartZone Holding BV - www.zmartzone.eu
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

#include <sys/types.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#else
#include "mmap-windows.c"
#ifdef _MSC_VER
#define _unlink unlink
#endif
#endif
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

#include "oauth2/ipc.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"
#include "oauth2/version.h"
#include "util_int.h"

// from the sema.h docs
#define _OAUTH2_IPC_NAME_MAX 63

static char *_oauth2_ipc_get_name(oauth2_log_t *log, const char *type,
				  void *ptr)
{
	char *rv = NULL;
	rv = oauth2_mem_alloc(_OAUTH2_IPC_NAME_MAX);
	// oauth2_snprintf(rv, _OAUTH2_IPC_NAME_MAX, "/zzo-%s-%ld.%p", type,
	//		(long int)getpid(), ptr);
	oauth2_snprintf(rv, _OAUTH2_IPC_NAME_MAX, "/zzo-%s-%p", type, ptr ? ptr : 0);
	//oauth2_snprintf(rv, _OAUTH2_IPC_NAME_MAX, "/zzo-%s", type);
	return rv;
}

/*
 * semaphore
 */

typedef struct oauth2_ipc_sema_t {
	char *name;
	sem_t *sema;
} oauth2_ipc_sema_t;

oauth2_ipc_sema_t *oauth2_ipc_sema_init(oauth2_log_t *log)
{
	oauth2_ipc_sema_t *s = oauth2_mem_alloc(sizeof(oauth2_ipc_sema_t));
	if (s) {
		s->sema = NULL;
	}
	return s;
}

void oauth2_ipc_sema_free(oauth2_log_t *log, oauth2_ipc_sema_t *s)
{
	if (s == NULL)
		goto end;

	if (s->sema != NULL) {
		if (sem_close(s->sema) != 0)
			oauth2_error(log, "sem_close() failed: %s ",
				     strerror(errno));
		s->sema = NULL;
	}

	if (s->name)
		oauth2_mem_free(s->name);

	oauth2_mem_free(s);

end:

	return;
}

bool oauth2_ipc_sema_post_config(oauth2_log_t *log, oauth2_ipc_sema_t *sema)
{
	bool rc = false;

	if (sema == NULL)
		goto end;

	if (sema->name) {
		oauth2_mem_free(sema->name);
		sema->name = NULL;
	}

	sema->name = _oauth2_ipc_get_name(log, "sema", sema);
	if (sema->name == NULL)
		goto end;

	sema->sema = sem_open(sema->name, O_CREAT, 0644, 0);
	if (sema->sema == SEM_FAILED) {
		oauth2_error(
		    log,
		    "sem_open() failed to create named semaphore %s: %s (%d)",
		    sema->name, strerror(errno), errno);
		sema->sema = NULL;
		goto end;
	}

	if (sem_unlink(sema->name) != 0)
		oauth2_error(log, "sem_unlink() failed: %s ", strerror(errno));

	rc = true;

end:

	return rc;
}

bool oauth2_ipc_sema_post(oauth2_log_t *log, oauth2_ipc_sema_t *sema)
{
	bool rc = false;
	int rv = 0;

	if ((sema == NULL) || (sema->sema == NULL))
		goto end;

	rv = sem_post(sema->sema);
	if (rv != 0) {
		oauth2_error(log, "sem_post() failed: %s (%d)", strerror(errno),
			     errno);
		goto end;
	}

	rc = true;

end:

	return rc;
}

bool oauth2_ipc_sema_wait(oauth2_log_t *log, oauth2_ipc_sema_t *sema)
{
	bool rc = true;
	int rv = 0;

	if ((sema == NULL) || (sema->sema == NULL))
		goto end;

	rv = sem_wait(sema->sema);
	if (rv != 0) {
		oauth2_error(log, "sem_wait() failed: %s (%d)", strerror(errno),
			     errno);
		goto end;
	}

	rc = true;

end:

	return rc;
}

bool oauth2_ipc_sema_trywait(oauth2_log_t *log, oauth2_ipc_sema_t *sema)
{
	bool rc = true;
	int rv = 0;

	if ((sema == NULL) || (sema->sema == NULL))
		goto end;

	rv = sem_trywait(sema->sema);

	if (rv != 0) {
		if (errno == EAGAIN)
			rc = false;
		else
			oauth2_error(log, "sem_trywait() failed: %s (%d)",
				     strerror(errno), errno);
	}

end:

	return rc;
}
/*
bool oauth2_ipc_sema_getvalue(oauth2_log_t *log, oauth2_ipc_sema_t *s, int
*value) { int rc = false; int rv = 0;

	rv = sem_getvalue(s->sema, value);
	if (rv != 0) {
		oauth2_error(log,
		  "sem_getvalue() failed: %s (%d)", strerror(errno), errno);
		goto end;
	}

	oauth2_debug(log, "semaphore: %d (s=%p)", *value, s);

	rc = true;

end:

	return rc;
}

*/

/*
 * mutex
 */

typedef struct oauth2_ipc_mutex_t {
	oauth2_ipc_sema_t *mutex;
} oauth2_ipc_mutex_t;

oauth2_ipc_mutex_t *oauth2_ipc_mutex_init(oauth2_log_t *log)
{
	oauth2_ipc_mutex_t *m = oauth2_mem_alloc(sizeof(oauth2_ipc_mutex_t));
	if (m) {
		m->mutex = oauth2_ipc_sema_init(log);
	}
	return m;
}

void oauth2_ipc_mutex_free(oauth2_log_t *log, oauth2_ipc_mutex_t *m)
{
	if ((m == NULL) && (m->mutex == NULL))
		goto end;

	oauth2_ipc_sema_free(log, m->mutex);
	m->mutex = NULL;
	oauth2_mem_free(m);

end:

	return;
}

bool oauth2_ipc_mutex_post_config(oauth2_log_t *log, oauth2_ipc_mutex_t *m)
{
	bool rc = false;

	if ((m == NULL) || (m->mutex == NULL))
		goto end;

	rc = oauth2_ipc_sema_post_config(log, m->mutex);
	if (rc == false)
		goto end;

	rc = oauth2_ipc_sema_post(log, m->mutex);

end:

	return rc;
}

bool oauth2_ipc_mutex_lock(oauth2_log_t *log, oauth2_ipc_mutex_t *m)
{
	bool rc = false;

	if ((m == NULL) || (m->mutex == NULL))
		goto end;

	rc = oauth2_ipc_sema_wait(log, m->mutex);

end:

	return rc;
}

bool oauth2_ipc_mutex_unlock(oauth2_log_t *log, oauth2_ipc_mutex_t *m)
{
	bool rc = false;

	if ((m == NULL) || (m->mutex == NULL))
		goto end;

	rc = oauth2_ipc_sema_post(log, m->mutex);

end:

	return rc;
}

/*
 * shared memory
 */

typedef struct oauth2_ipc_shm_t {
	char *name;
	// int fd;
	oauth2_ipc_mutex_t *mutex;
	oauth2_ipc_sema_t *num;
	size_t size;
	void *ptr;
} oauth2_ipc_shm_t;

oauth2_ipc_shm_t *oauth2_ipc_shm_init(oauth2_log_t *log, size_t size)
{
	oauth2_ipc_shm_t *shm = oauth2_mem_alloc(sizeof(oauth2_ipc_shm_t));
	shm->mutex = oauth2_ipc_mutex_init(log);
	// shm->fd = -1;
	shm->num = oauth2_ipc_sema_init(log);
	shm->name = NULL;
	shm->ptr = NULL;
	shm->size = size;
	return shm;
}

void oauth2_ipc_shm_free(oauth2_log_t *log, oauth2_ipc_shm_t *shm)
{
	bool rc = false;
	int rv = 0;

	if (shm == NULL)
		goto end;

	if (shm->mutex)
		oauth2_ipc_mutex_free(log, shm->mutex);
	shm->mutex = NULL;

	if (shm->ptr) {
		if (munmap(shm->ptr, shm->size) < 0)
			oauth2_error(log, "munmap() failed: %s",
				     strerror(errno));
		shm->ptr = NULL;
	}

	if (shm->num) {
		// if we cannot lock it, it is 0
		// TODO: isn't close enough?
		rc = oauth2_ipc_sema_trywait(log, shm->num);
		if (rc == false) {
			rv = shm_unlink(shm->name);
			oauth2_error(log, "shm_unlink() failed: %s (%d)",
				     strerror(errno), rv);
		}
		oauth2_ipc_sema_free(log, shm->num);
		shm->num = NULL;
		oauth2_debug(log, "destroyed shm with name: %s", shm->name);
	}

	if (shm->name)
		oauth2_mem_free(shm->name);

	oauth2_mem_free(shm);

end:

	return;
}

bool oauth2_ipc_shm_post_config(oauth2_log_t *log, oauth2_ipc_shm_t *shm)
{
	bool rc = false;
	int fd = -1;

	if (shm == NULL)
		goto end;

	rc = oauth2_ipc_sema_post_config(log, shm->num);
	if (rc == false)
		goto end;

	rc = oauth2_ipc_mutex_post_config(log, shm->mutex);
	if (rc == false)
		goto end;

	shm->name = _oauth2_ipc_get_name(log, "shm", shm);
	if (shm->name == NULL)
		goto end;

	oauth2_debug(log, "creating shm with name: %s", shm->name);

	fd = shm_open(shm->name, O_CREAT | O_RDWR, 0666);
	if (fd == -1) {
		oauth2_error(log, "shm_open() failed: %s", strerror(errno));
		goto end;
	}

	if (ftruncate(fd, shm->size) != 0) {
		oauth2_error(log, "ftruncate() failed: %s", strerror(errno));
		//goto end;
	}

	shm->ptr =
	    mmap(0, shm->size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1 /*fd*/, 0);
	if (shm->ptr == MAP_FAILED) {
		oauth2_error(log, "mmap() failed: %s", strerror(errno));
		goto end;
	}

	rc = oauth2_ipc_sema_post(log, shm->num);

end:

	if (fd != -1)
		close(fd);

	return rc;
}

bool oauth2_ipc_shm_child_init(oauth2_log_t *log, oauth2_ipc_shm_t *shm)
{
	return shm ? oauth2_ipc_sema_post(log, shm->num) : false;
}

void *oauth2_ipc_shm_get(oauth2_log_t *log, oauth2_ipc_shm_t *shm)
{
	return shm ? shm->ptr : NULL;
}
