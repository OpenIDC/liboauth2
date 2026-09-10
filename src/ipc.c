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

#ifdef _WIN32
/*
 * Windows has no fork(): Apache's mpm_winnt runs a single multi-threaded child
 * process that reads the configuration itself, so the "inter-process"
 * primitives in this file only ever coordinate threads within one process
 * there. They are implemented on the corresponding Win32 kernel objects and on
 * process heap memory rather than on the POSIX named semaphores and anonymous
 * shared mappings that are inherited across fork() elsewhere.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <string.h>

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
	oauth2_snprintf(rv, _OAUTH2_IPC_NAME_MAX, "/zzo-%s-%ld.%p", type,
			(long int)getpid(), ptr ? ptr : 0);
	return rv;
}

/*
 * semaphore
 */

typedef struct oauth2_ipc_sema_t {
	char *name;
#ifdef _WIN32
	HANDLE sema;
#else
	sem_t *sema;
#endif
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
#ifdef _WIN32
		if (CloseHandle(s->sema) == 0)
			oauth2_error(log, "CloseHandle() failed: %lu",
				     GetLastError());
#else
		if (sem_close(s->sema) != 0)
			oauth2_error(log, "sem_close() failed: %s ",
				     strerror(errno));
#endif
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

#ifdef _WIN32
	// unnamed: nothing forks, see the note at the top of this file
	sema->sema = CreateSemaphoreA(NULL, 0, LONG_MAX, NULL);
	if (sema->sema == NULL) {
		oauth2_error(log,
			     "CreateSemaphore() failed to create semaphore "
			     "%s: %lu",
			     sema->name, GetLastError());
		goto end;
	}
#else
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
#endif

	rc = true;

end:

	return rc;
}

bool oauth2_ipc_sema_post(oauth2_log_t *log, oauth2_ipc_sema_t *sema)
{
	bool rc = false;

	if ((sema == NULL) || (sema->sema == NULL))
		goto end;

#ifdef _WIN32
	if (ReleaseSemaphore(sema->sema, 1, NULL) == 0) {
		oauth2_error(log, "ReleaseSemaphore() failed: %lu",
			     GetLastError());
		goto end;
	}
#else
	if (sem_post(sema->sema) != 0) {
		oauth2_error(log, "sem_post() failed: %s (%d)", strerror(errno),
			     errno);
		goto end;
	}
#endif

	rc = true;

end:

	return rc;
}

bool oauth2_ipc_sema_wait(oauth2_log_t *log, oauth2_ipc_sema_t *sema)
{
	bool rc = false;

	if ((sema == NULL) || (sema->sema == NULL))
		goto end;

#ifdef _WIN32
	if (WaitForSingleObject(sema->sema, INFINITE) != WAIT_OBJECT_0) {
		oauth2_error(log, "WaitForSingleObject() failed: %lu",
			     GetLastError());
		goto end;
	}
#else
	if (sem_wait(sema->sema) != 0) {
		oauth2_error(log, "sem_wait() failed: %s (%d)", strerror(errno),
			     errno);
		goto end;
	}
#endif

	rc = true;

end:

	return rc;
}

bool oauth2_ipc_sema_trywait(oauth2_log_t *log, oauth2_ipc_sema_t *sema)
{
	bool rc = false;

	if ((sema == NULL) || (sema->sema == NULL))
		goto end;

#ifdef _WIN32
	switch (WaitForSingleObject(sema->sema, 0)) {
	case WAIT_OBJECT_0:
		rc = true;
		break;
	case WAIT_TIMEOUT:
		break;
	default:
		oauth2_error(log, "WaitForSingleObject() failed: %lu",
			     GetLastError());
		break;
	}
#else
	if (sem_trywait(sema->sema) == 0)
		rc = true;
	else if (errno != EAGAIN)
		oauth2_error(log, "sem_trywait() failed: %s (%d)",
			     strerror(errno), errno);
#endif

end:

	return rc;
}

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
	if ((m == NULL) || (m->mutex == NULL))
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
 * thread mutex
 */

typedef struct oauth2_ipc_thread_mutex_t {
#ifdef _WIN32
	CRITICAL_SECTION mutex;
#else
	pthread_mutex_t mutex;
#endif
} oauth2_ipc_thread_mutex_t;

oauth2_ipc_thread_mutex_t *oauth2_ipc_thread_mutex_init(oauth2_log_t *log)
{
	oauth2_ipc_thread_mutex_t *m =
	    oauth2_mem_alloc(sizeof(oauth2_ipc_thread_mutex_t));
	if (m) {
#ifdef _WIN32
		InitializeCriticalSection(&m->mutex);
#else
		pthread_mutex_init(&m->mutex, NULL);
#endif
	}
	return m;
}

void oauth2_ipc_thread_mutex_free(oauth2_log_t *log,
				  oauth2_ipc_thread_mutex_t *m)
{
	if (m == NULL)
		goto end;
#ifdef _WIN32
	DeleteCriticalSection(&m->mutex);
#else
	pthread_mutex_destroy(&m->mutex);
#endif
	oauth2_mem_free(m);

end:

	return;
}

bool oauth2_ipc_thread_mutex_lock(oauth2_log_t *log,
				  oauth2_ipc_thread_mutex_t *m)
{
	bool rc = false;

	if (m == NULL)
		goto end;

#ifdef _WIN32
	EnterCriticalSection(&m->mutex);
	rc = true;
#else
	rc = (pthread_mutex_lock(&m->mutex) == 0);
#endif

end:

	return rc;
}

bool oauth2_ipc_thread_mutex_unlock(oauth2_log_t *log,
				    oauth2_ipc_thread_mutex_t *m)
{
	bool rc = false;

	if (m == NULL)
		goto end;

#ifdef _WIN32
	LeaveCriticalSection(&m->mutex);
	rc = true;
#else
	rc = (pthread_mutex_unlock(&m->mutex) == 0);
#endif

end:

	return rc;
}

/*
 * shared memory
 */

typedef struct oauth2_ipc_shm_t {
	oauth2_ipc_mutex_t *mutex;
	oauth2_ipc_sema_t *num;
	size_t size;
	void *ptr;
} oauth2_ipc_shm_t;

oauth2_ipc_shm_t *oauth2_ipc_shm_init(oauth2_log_t *log, size_t size)
{
	oauth2_ipc_shm_t *shm = oauth2_mem_alloc(sizeof(oauth2_ipc_shm_t));
	shm->mutex = oauth2_ipc_mutex_init(log);
	shm->num = oauth2_ipc_sema_init(log);
	shm->ptr = NULL;
	shm->size = size;
	return shm;
}

void oauth2_ipc_shm_free(oauth2_log_t *log, oauth2_ipc_shm_t *shm)
{
	if (shm == NULL)
		goto end;

	if (shm->mutex)
		oauth2_ipc_mutex_free(log, shm->mutex);
	shm->mutex = NULL;

	if (shm->ptr) {
#ifdef _WIN32
		if (HeapFree(GetProcessHeap(), 0, shm->ptr) == 0)
			oauth2_error(log, "HeapFree() failed: %lu",
				     GetLastError());
#else
		if (munmap(shm->ptr, shm->size) < 0)
			oauth2_error(log, "munmap() failed: %s",
				     strerror(errno));
#endif
		shm->ptr = NULL;
	}

	if (shm->num) {
		oauth2_ipc_sema_free(log, shm->num);
		shm->num = NULL;
	}

	oauth2_mem_free(shm);

end:

	return;
}

bool oauth2_ipc_shm_post_config(oauth2_log_t *log, oauth2_ipc_shm_t *shm)
{
	bool rc = false;

	if (shm == NULL)
		goto end;

	rc = oauth2_ipc_sema_post_config(log, shm->num);
	if (rc == false)
		goto end;

	rc = oauth2_ipc_mutex_post_config(log, shm->mutex);
	if (rc == false)
		goto end;

#ifdef _WIN32
	// process-local and zeroed, like the anonymous mapping below; taken
	// from the process heap rather than through oauth2_mem_alloc so that it
	// does not follow an allocator that was redirected onto a pool
	oauth2_debug(log, "allocating shm block from the process heap");

	shm->ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, shm->size);
	if (shm->ptr == NULL) {
		oauth2_error(log, "HeapAlloc() failed: %lu", GetLastError());
		goto end;
	}
#else
	oauth2_debug(log, "creating anonymous shm");

	shm->ptr = mmap(0, shm->size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shm->ptr == MAP_FAILED) {
		oauth2_error(log, "mmap() failed: %s", strerror(errno));
		goto end;
	}
#endif

	rc = oauth2_ipc_sema_post(log, shm->num);

end:

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
