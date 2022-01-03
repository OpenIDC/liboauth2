/***************************************************************************
 *
 * Copyright (C) 2018-2022 - ZmartZone Holding BV - www.zmartzone.eu
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

#include <string.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "oauth2/cache.h"
#include "oauth2/ipc.h"
#include "oauth2/jose.h"
#include "oauth2/mem.h"
#include "oauth2/util.h"

#include "cache_int.h"
#include "cfg_int.h"
#include "util_int.h"

_OAUTH2_CFG_GLOBAL_LIST(cache_type, oauth2_cache_type_t)
_OAUTH2_CFG_GLOBAL_LIST(cache, oauth2_cache_t)

extern oauth2_cache_type_t oauth2_cache_shm;
extern oauth2_cache_type_t oauth2_cache_file;
#ifdef HAVE_LIBMEMCACHE
extern oauth2_cache_type_t oauth2_cache_memcache;
#endif
#ifdef HAVE_LIBHIREDIS
extern oauth2_cache_type_t oauth2_cache_redis;
#endif

#define _OAUTH2_CACHE_OPENSSL_ERR ERR_error_string(ERR_get_error(), NULL)

static bool _oauth2_cache_global_initialized = false;

static void _oauth2_cache_global_init(oauth2_log_t *log)
{
	if (_oauth2_cache_global_initialized == true)
		goto end;

	_M_cache_type_list_register(log, oauth2_cache_shm.name,
				    &oauth2_cache_shm, NULL);
	_M_cache_type_list_register(log, oauth2_cache_file.name,
				    &oauth2_cache_file, NULL);
#ifdef HAVE_LIBMEMCACHE
	_M_cache_type_list_register(log, oauth2_cache_memcache.name,
				    &oauth2_cache_memcache, NULL);
#endif
#ifdef HAVE_LIBHIREDIS
	_M_cache_type_list_register(log, oauth2_cache_redis.name,
				    &oauth2_cache_redis, NULL);
#endif

	_oauth2_cache_global_initialized = true;

end:

	return;
}

static void _oauth2_cache_free(oauth2_log_t *log, oauth2_cache_t *cache)
{
	oauth2_debug(log, "enter");

	if ((cache == NULL) || (cache->type == NULL))
		goto end;

	if (cache->key_hash_algo)
		oauth2_mem_free(cache->key_hash_algo);
	if (cache->enc_key)
		oauth2_mem_free(cache->enc_key);
	if (cache->passphrase_hash_algo)
		oauth2_mem_free(cache->passphrase_hash_algo);

	if (cache->type->free)
		cache->type->free(log, cache);
	oauth2_mem_free(cache);

end:

	oauth2_debug(log, "leave");

	return;
}

oauth2_cache_t *_oauth2_cache_init(oauth2_log_t *log, const char *type,
				   const oauth2_nv_list_t *params)
{
	oauth2_cache_t *cache = NULL;
	oauth2_cache_type_t *cache_type = NULL;

	_oauth2_cache_global_init(log);

	if (type == NULL)
		type = "shm";

	cache_type = _M_cache_type_list_get(log, type);
	if (cache_type == NULL) {
		oauth2_error(log, "cache type %s is not registered", type);
		goto end;
	}

	if (cache_type->init == NULL)
		goto end;

	cache = oauth2_mem_alloc(sizeof(oauth2_cache_t));
	if (cache == NULL)
		goto end;

	if (cache_type->init(log, cache, params) == false)
		goto end;

	cache->key_hash_algo =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "key_hash_algo"));
	cache->passphrase_hash_algo = oauth2_strdup(
	    oauth2_nv_list_get(log, params, "passphrase_hash_algo"));
	cache->encrypt =
	    oauth2_parse_bool(log, oauth2_nv_list_get(log, params, "encrypt"),
			      cache->type->encrypt_by_default);

	if (cache->encrypt == false) {
		cache->enc_key = NULL;
		goto end;
	}

end:

	if (cache)
		_M_cache_list_register(log,
				       oauth2_nv_list_get(log, params, "name"),
				       cache, _oauth2_cache_free);

	return cache;
}

oauth2_cache_t *oauth2_cache_obtain(oauth2_log_t *log, const char *name)
{
	oauth2_cache_t *c = NULL;

	oauth2_debug(log, "enter: %s", name);

	if (_M_cache_list_empty(log)) {
		c = _oauth2_cache_init(log, NULL, NULL);
		if (c == NULL)
			goto end;
		if (_oauth2_cache_post_config(log, c) == false) {
			c = NULL;
			goto end;
		}
	}

	c = _M_cache_list_get(log, name);

end:

	oauth2_debug(log, "leave: %p", c);

	return c;
}

void _oauth2_cache_global_cleanup(oauth2_log_t *log)
{
	oauth2_debug(log, "enter");
	_M_cache_list_release(log);
	_M_cache_type_list_release(log);
	_oauth2_cache_global_initialized = false;
	oauth2_debug(log, "leave");
}

bool _oauth2_cache_post_config(oauth2_log_t *log, oauth2_cache_t *cache)
{
	bool rc = false;

	oauth2_debug(log, "enter");

	if ((cache == NULL) || (cache->type == NULL))
		goto end;

	if (cache->type->post_config == NULL) {
		rc = true;
		goto end;
	}

	rc = cache->type->post_config(log, cache);

end:

	oauth2_debug(log, "return: %d", rc);

	return rc;
}

bool oauth2_cache_child_init(oauth2_log_t *log, oauth2_cache_t *cache)
{
	bool rc = false;

	if ((cache == NULL) || (cache->type == NULL))
		goto end;

	if (cache->type->child_init == NULL) {
		rc = true;
		goto end;
	}

	rc = cache->type->child_init(log, cache);

end:

	return rc;
}

static bool _oauth2_cache_hash_key(oauth2_log_t *log, const char *key,
				   const char *algo, char **hash)
{
	bool rc = false;

	oauth2_debug(log, "enter: key=%s, algo=%s", key, algo);

	if ((algo) && (strcmp(algo, "none") == 0)) {
		*hash = oauth2_strdup(key);
		rc = true;
		goto end;
	}

	if (algo == NULL)
		algo = OAUTH2_JOSE_OPENSSL_ALG_SHA256;

	rc = oauth2_jose_hash2s(log, algo, key, hash);

end:

	oauth2_debug(log, "leave: hashed key: %s", *hash);

	return rc;
}

static const char *_oauth_cache_get_enc_key(oauth2_log_t *log,
					    oauth2_cache_t *cache)
{

	const char *passphrase = NULL, *passphrase_hash_algo = NULL;

	if (cache->enc_key != NULL)
		goto end;

	passphrase = oauth2_crypto_passphrase_get(log);
	if (passphrase == NULL)
		goto end;

	passphrase_hash_algo = cache->passphrase_hash_algo
				   ? passphrase_hash_algo
				   : OAUTH2_JOSE_OPENSSL_ALG_SHA256;

	if (strcmp(passphrase_hash_algo, "none") == 0) {
		cache->enc_key = oauth2_strdup(passphrase);
	} else {
		//		if (oauth2_jose_hash_bytes(log,
		//passphrase_hash_algo, 					   (const unsigned char *)passphrase,
		//					   strlen(passphrase),
		//&cache->enc_key, 					   &enc_key_len) == false) {
		if (oauth2_jose_hash2s(log, passphrase_hash_algo, passphrase,
				       &cache->enc_key) == false) {
			oauth2_error(
			    log, "could not hash cache encryption passphrase");
			goto end;
		}
	}

end:

	return cache->enc_key;
}

static int oauth2_cache_decrypt(oauth2_log_t *log, oauth2_cache_t *cache,
				const char *value, char **plaintext)
{
	int len = -1;

	oauth2_debug(log, "enter");

	if (oauth2_jose_decrypt(
		log, (const char *)_oauth_cache_get_enc_key(log, cache), value,
		plaintext) == false)
		goto end;

	len = strlen(*plaintext);

end:

	oauth2_debug(log, "leave: len=%d", len);

	return len;
}

bool oauth2_cache_get(oauth2_log_t *log, oauth2_cache_t *cache, const char *key,
		      char **value)
{
	bool rc = false;
	char *hashed_key = NULL;
	char *encrypted_value = NULL;

	oauth2_debug(log, "enter: key=%s, type=%s, decrypt=%d",
		     key ? key : "<null>",
		     cache && cache->type ? cache->type->name : "<n/a>",
		     cache ? cache->encrypt : -1);

	if ((cache == NULL) || (cache->type == NULL) ||
	    (cache->type->get == NULL) || (key == NULL) || (value == NULL))
		goto end;

	if (_oauth2_cache_hash_key(log, key, cache->key_hash_algo,
				   &hashed_key) == false)
		goto end;

	if (cache->type->get(log, cache, hashed_key, value) == false)
		goto end;

	if ((cache->encrypt) && (*value)) {
		if (oauth2_cache_decrypt(log, cache, *value, &encrypted_value) <
		    0) {
			oauth2_mem_free(*value);
			*value = NULL;
			goto end;
		}
		oauth2_mem_free(*value);
		*value = encrypted_value;
	}

	rc = true;

end:

	if (hashed_key)
		oauth2_mem_free(hashed_key);

	oauth2_debug(log, "leave: cache %s for key: %s return: %lu bytes",
		     rc ? (*value ? "hit" : "miss") : "error",
		     key ? key : "<null>",
		     *value ? (unsigned long)strlen(*value) : 0);

	return rc;
}

static int oauth2_cache_encrypt(oauth2_log_t *log, oauth2_cache_t *cache,
				const char *plaintext, char **result)
{
	int len = -1;

	oauth2_debug(log, "enter: %s", plaintext);

	if (oauth2_jose_encrypt(
		log, (const char *)_oauth_cache_get_enc_key(log, cache),
		plaintext, result) == false)
		goto end;

	len = strlen(*result);

end:

	oauth2_debug(log, "leave: len=%d", (int)len);

	return len;
}

bool oauth2_cache_set(oauth2_log_t *log, oauth2_cache_t *cache, const char *key,
		      const char *value, oauth2_time_t ttl_s)
{

	bool rc = false;
	char *hashed_key = NULL;
	char *encrypted = NULL;

	oauth2_debug(log,
		     "enter: key=%s, len=%lu, ttl(s)=" OAUTH2_TIME_T_FORMAT
		     ", type=%s, encrypt=%d",
		     key ? key : "<null>",
		     value ? (unsigned long)strlen(value) : 0, ttl_s,
		     (cache && cache->type) ? cache->type->name : "<n/a>",
		     cache ? cache->encrypt : -1);

	if ((cache == NULL) || (cache->type == NULL) ||
	    (cache->type->set == NULL) || (key == NULL))
		goto end;

	if (_oauth2_cache_hash_key(log, key, cache->key_hash_algo,
				   &hashed_key) == false)
		goto end;

	if ((cache->encrypt) && (value))
		if (oauth2_cache_encrypt(log, cache, value, &encrypted) < 0)
			goto end;

	if (cache->type->set(log, cache, hashed_key,
			     encrypted ? encrypted : value, ttl_s) == false) {
		goto end;
	}

	rc = true;

end:

	if (hashed_key)
		oauth2_mem_free(hashed_key);
	if (encrypted)
		oauth2_mem_free(encrypted);

	if (rc)
		oauth2_debug(log, "leave: successfully stored: %s",
			     key ? key : "<null>");
	else
		oauth2_error(log, "leave: could NOT store: %s",
			     key ? key : "<null>");

	return rc;
}
