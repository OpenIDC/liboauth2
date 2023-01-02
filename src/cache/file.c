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

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#define _unlink unlink
#endif

#include <oauth2/cache.h>
#include <oauth2/ipc.h>
#include <oauth2/mem.h>
#include <oauth2/util.h>

#include "cache_int.h"

typedef struct oauth2_cache_impl_file_t {
	oauth2_ipc_mutex_t *mutex;
	char *dir;
	oauth2_time_t clean_interval;
} oauth2_cache_impl_file_t;

typedef struct {
	oauth2_uint_t len;
	oauth2_time_t expire;
} oauth2_cache_file_info_t;

#define OAUTH2_CACHE_FILE_PREFIX "oauth2-cache-"

oauth2_cache_type_t oauth2_cache_file;

static bool oauth2_cache_file_init(oauth2_log_t *log, oauth2_cache_t *cache,
				   const oauth2_nv_list_t *options)
{
	bool rc = false;
	const char *v = NULL;
	oauth2_cache_impl_file_t *impl = NULL;

	oauth2_debug(log, "enter");

	impl = oauth2_mem_alloc(sizeof(oauth2_cache_impl_file_t));
	if (impl == NULL)
		goto end;

	cache->impl = impl;
	cache->type = &oauth2_cache_file;

	impl->mutex = oauth2_ipc_mutex_init(log);
	if (impl->mutex == NULL)
		goto end;

	v = oauth2_nv_list_get(log, options, "dir");
	if (v == NULL) {
#ifdef WIN32
		v = "C:\\TEMP";
#else
		v = "/tmp";
#endif
	}

	impl->dir = oauth2_strdup(v);

	v = oauth2_nv_list_get(log, options, "clean_interval");
	impl->clean_interval = oauth2_parse_time_sec(log, v, 60);

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_file_free(oauth2_log_t *log, oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_file_t *impl =
	    (oauth2_cache_impl_file_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	if (impl->mutex != NULL) {
		oauth2_ipc_mutex_free(log, impl->mutex);
		impl->mutex = NULL;
	}

	if (impl->dir) {
		oauth2_mem_free(impl->dir);
		impl->dir = NULL;
	}

	oauth2_mem_free(impl);
	cache->impl = NULL;

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_file_post_config(oauth2_log_t *log,
					  oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_file_t *impl =
	    (oauth2_cache_impl_file_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	rc = oauth2_ipc_mutex_post_config(log, impl->mutex);
	if (rc == false)
		goto end;

	// TODO: check directory accessibility ?

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool oauth2_cache_file_child_init(oauth2_log_t *log,
					 oauth2_cache_t *cache)
{
	bool rc = false;
	oauth2_cache_impl_file_t *impl =
	    (oauth2_cache_impl_file_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	// TOOD: nothing? then put function pointer in type struct to NULL

	rc = true;

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static char *_oauth2_cache_file_path(oauth2_log_t *log,
				     oauth2_cache_impl_file_t *impl,
				     const char *key)
{
	char *path = NULL;

	// TODO: WIN32 \ ?
	path = oauth2_strdup(impl->dir);
	path = oauth2_stradd(path, "/", OAUTH2_CACHE_FILE_PREFIX, key);

	return path;
}

static bool _oauth2_cache_file_read(oauth2_log_t *log, FILE *f, void *buf,
				    const size_t len)
{
	bool rc = false;
	int n = 0;

	n = fread(buf, 1, len, f);

	if (n <= 0) {
		oauth2_error(log, "fread failed: %s", strerror(errno));
		goto end;
	}

	if (n != len) {
		oauth2_error(log,
			     "fread returned %zu bytes but requested %zu bytes",
			     n, len);
		goto end;
	}

	rc = true;

end:

	return rc;
}

static bool _oauth2_cache_file_remove(oauth2_log_t *log, const char *path)
{
	bool rc = true;

	if (_unlink(path) != 0) {
		oauth2_error(log, "could not delete cache file \"%s\" (%s)",
			     path, strerror(errno));
		rc = false;
	}

	return rc;
}

static bool oauth2_cache_file_get(oauth2_log_t *log, oauth2_cache_t *cache,
				  const char *key, char **value)
{

	bool rc = false;
	char *path = NULL;
	FILE *f = NULL;
	oauth2_cache_file_info_t info;
	oauth2_cache_impl_file_t *impl =
	    (oauth2_cache_impl_file_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	// TODO:
	// if (oauth2_cache_shm_check_key(log, impl, key) == false)
	//	goto end;
	//
	// and/or url-encode to make a valid filename?

	*value = NULL;

	path = _oauth2_cache_file_path(log, cache->impl, key);

	if (oauth2_ipc_mutex_lock(log, impl->mutex) == false)
		goto end;

	f = fopen(path, "rb");
	if (f == NULL) {
		if (errno == ENOENT) {
			oauth2_debug(log, "cache miss for key \"%s\"", key);
			rc = true;
		} else {
			oauth2_error(log, "fopen failed: %s", strerror(errno));
		}
		goto unlock;
	}

	if (fseek(f, 0, SEEK_SET) != 0) {
		oauth2_error(log, "fseek failed: %s", strerror(errno));
		goto unlock;
	}

	if (_oauth2_cache_file_read(log, f, &info,
				    sizeof(oauth2_cache_file_info_t)) == false)
		goto unlock;

	if (oauth2_time_now_sec() >= info.expire) {

		fclose(f);
		f = NULL;

		oauth2_debug(log,
			     "cache entry \"%s\" expired, removing file \"%s\"",
			     key, path);

		rc = _oauth2_cache_file_remove(log, path);

		goto unlock;
	}

	*value = oauth2_mem_alloc(info.len);
	if (*value == NULL)
		goto unlock;

	rc = _oauth2_cache_file_read(log, f, (void *)*value, info.len);

unlock:

	oauth2_ipc_mutex_unlock(log, impl->mutex);

end:

	if (f)
		fclose(f);
	if (path)
		oauth2_mem_free(path);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _oauth2_cache_file_write(oauth2_log_t *log, FILE *f, void *buf,
				     const size_t len)
{
	bool rc = false;
	int n = 0;

	n = fwrite(buf, 1, len, f);

	if (n <= 0) {
		oauth2_error(log, "fwrite failed: %s", strerror(errno));
		goto end;
	}

	if (n != len) {
		oauth2_error(
		    log, "fwrite returned %zu bytes but requested %zu bytes", n,
		    len);
		goto end;
	}

	rc = true;

end:

	return rc;
}

#ifdef __APPLE__
#ifndef st_mtime
#define st_mtime st_mtimespec.tv_sec
#endif
#endif

static void _oauth2_cache_files_clean(oauth2_log_t *log,
				      oauth2_cache_impl_file_t *impl)
{
	bool rc = false;
	char *path = NULL, *fpath = NULL, *filename = NULL;
	struct stat fi;
	FILE *f = NULL;
	DIR *d = NULL;
	struct dirent *dep = NULL;
	oauth2_cache_file_info_t info;

	// TODO: pretty unique, right?
	path = oauth2_stradd(NULL, impl->dir, "/", "__oauth2-cache-cleaned__");

	if (stat(path, &fi) == 0) {

		if (oauth2_time_now_sec() <
		    (fi.st_mtime + impl->clean_interval)) {
			oauth2_debug(log,
				     "last cleanup call was less "
				     "than " OAUTH2_TIME_T_FORMAT
				     " seconds ago (next one as early as "
				     "in " OAUTH2_TIME_T_FORMAT " secs)",
				     impl->clean_interval,
				     fi.st_mtime + impl->clean_interval -
					 oauth2_time_now_sec());
			goto end;
		}

		oauth2_debug(log, "start cleaning cycle");
	}

	// create and/or set file modification time
	f = fopen(path, "wb");
	if (f == NULL) {
		oauth2_error(log, "fopen failed: %s", strerror(errno));
		goto end;
	}
	_oauth2_cache_file_write(log, f, (void *)"", 1);
	fclose(f);
	f = NULL;

	d = opendir(impl->dir);
	if (d == NULL) {
		oauth2_error(log, "opendir failed: %s", strerror(errno));
		goto end;
	}

	while ((dep = readdir(d))) {

		filename = oauth2_stradd(NULL, impl->dir, "/", dep->d_name);
		if (filename == NULL)
			goto cont;

		if (stat(filename, &fi) != 0) {
			oauth2_error(log, "stat failed on %s: %s\n", filename,
				     strerror(errno));
			goto cont;
		}

		if ((fi.st_mode & S_IFMT) == S_IFDIR)
			goto cont;

		if (strstr(dep->d_name, OAUTH2_CACHE_FILE_PREFIX) !=
		    dep->d_name)
			goto cont;

		fpath = oauth2_stradd(NULL, impl->dir, "/", dep->d_name);
		if (fpath == NULL)
			goto cont;

		f = fopen(fpath, "rb");
		if (f == NULL) {
			oauth2_error(log, "fopen failed: %s", strerror(errno));
			goto cont;
		}

		rc = _oauth2_cache_file_read(log, f, &info,
					     sizeof(oauth2_cache_file_info_t));

		if ((rc == false) || (oauth2_time_now_sec() < info.expire)) {
			oauth2_debug(
			    log,
			    "cache entry (%s) expired, removing file \"%s\")",
			    dep->d_name, fpath);
			if (_oauth2_cache_file_remove(log, fpath) == false) {
				oauth2_error(log,
					     "could not delete cache file: %s",
					     fpath);
			}
		}

	cont:
		if (f) {
			fclose(f);
			f = NULL;
		}
		if (filename) {
			oauth2_mem_free(filename);
			filename = NULL;
		}
		if (fpath) {
			oauth2_mem_free(fpath);
			fpath = NULL;
		}
		continue;
	}

end:

	if (d)
		closedir(d);
	if (path)
		oauth2_mem_free(path);

	return;
}

static bool oauth2_cache_file_set(oauth2_log_t *log, oauth2_cache_t *cache,
				  const char *key, const char *value,
				  oauth2_time_t ttl_s)
{
	bool rc = false;
	char *path = NULL;
	FILE *f = NULL;
	oauth2_cache_file_info_t info;
	oauth2_cache_impl_file_t *impl =
	    (oauth2_cache_impl_file_t *)cache->impl;

	oauth2_debug(log, "enter");

	if (impl == NULL)
		goto end;

	/*
	 * TODO:
	if (oauth2_cache_shm_check_key(log, impl, key) == false)
		goto end;
	if (oauth2_cache_shm_check_value(log, impl, value) == false)
		goto end;
	 */

	path = _oauth2_cache_file_path(log, impl, key);

	if (oauth2_ipc_mutex_lock(log, impl->mutex) == false)
		goto end;

	_oauth2_cache_files_clean(log, impl);

	if (value == NULL) {
		rc = (access(path, F_OK) == 0)
			 ? _oauth2_cache_file_remove(log, path)
			 : true;
		goto unlock;
	}

	f = fopen(path, "wb");
	if (f == NULL) {
		oauth2_error(log, "fopen failed: %s", strerror(errno));
		goto unlock;
	}

	if (fseek(f, 0, SEEK_SET) != 0) {
		oauth2_error(log, "fseek failed: %s", strerror(errno));
		goto unlock;
	}

	info.expire = oauth2_time_now_sec() + ttl_s;
	info.len = strlen(value) + 1;

	if (_oauth2_cache_file_write(log, f, &info,
				     sizeof(oauth2_cache_file_info_t)) == false)
		goto unlock;

	rc = _oauth2_cache_file_write(log, f, (void *)value, info.len);

unlock:

	oauth2_ipc_mutex_unlock(log, impl->mutex);

end:

	if (f)
		fclose(f);
	if (path)
		oauth2_mem_free(path);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

OAUTH2_CACHE_TYPE_DECLARE(file, true)
