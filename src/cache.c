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
#include "util_int.h"

typedef struct oauth2_cache_type_list_t {
	oauth2_cache_type_t *type;
	struct oauth2_cache_type_list_t *next;
} oauth2_cache_type_list_t;

static oauth2_cache_type_list_t *_cache_types = NULL;

typedef struct oauth2_cache_list_t {
	char *name;
	oauth2_cache_t *cache;
	struct oauth2_cache_list_t *next;
} oauth2_cache_list_t;

static oauth2_cache_list_t *_cache_list = NULL;

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

static void _oauth2_cache_global_init()
{

	if (_oauth2_cache_global_initialized == true)
		goto end;

	// TODO: unregister on shutdown
	_oauth2_cache_type_register(&oauth2_cache_shm);
	_oauth2_cache_type_register(&oauth2_cache_file);
#ifdef HAVE_LIBMEMCACHE
	_oauth2_cache_type_register(&oauth2_cache_memcache);
#endif
#ifdef HAVE_LIBHIREDIS
	_oauth2_cache_type_register(&oauth2_cache_redis);
#endif

	_oauth2_cache_global_initialized = true;

end:

	return;
}

static void _oauth2_cache_register(oauth2_log_t *log, const char *name,
				   oauth2_cache_t *cache);

oauth2_cache_t *oauth2_cache_init(oauth2_log_t *log, const char *type,
				  const oauth2_nv_list_t *params)
{
	oauth2_cache_t *cache = NULL;
	oauth2_cache_type_list_t *list_ptr = NULL;
	char *passphrase = NULL;
	const char *passphrase_hash_algo = NULL;
	unsigned int enc_key_len = -1;

	_oauth2_cache_global_init();

	list_ptr = _cache_types;

	if (type == NULL)
		type = "shm";

	while (list_ptr && strcmp(list_ptr->type->name, type) != 0)
		list_ptr = list_ptr->next;

	if (list_ptr == NULL) {
		oauth2_error(log, "cache type %s is not registered", type);
		goto end;
	}

	if ((list_ptr->type == NULL) || (list_ptr->type->init == NULL))
		goto end;

	cache = oauth2_mem_alloc(sizeof(oauth2_cache_t));
	if (cache == NULL)
		goto end;

	if (list_ptr->type->init(log, cache, params) == false)
		goto end;

	cache->refcount = 1;
	cache->key_hash_algo =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "key_hash_algo"));
	cache->encrypt =
	    oauth2_parse_bool(log, oauth2_nv_list_get(log, params, "encrypt"),
			      cache->type->encrypt_by_default);

	if (cache->encrypt == false) {
		cache->enc_key = NULL;
		goto end;
	}

	passphrase =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "passphrase"));
	if (passphrase == NULL)
		// assumes that the cache parameters are configured in the same
		// order on different cache sharing instances...
		passphrase = oauth2_nv_list2s(log, params);

	passphrase_hash_algo =
	    oauth2_nv_list_get(log, params, "passphrase_hash_algo");
	if (passphrase_hash_algo == NULL)
		passphrase_hash_algo = OAUTH2_JOSE_OPENSSL_ALG_SHA256;

	if (strcmp(passphrase_hash_algo, "none") == 0) {
		cache->enc_key = (unsigned char *)oauth2_strdup(passphrase);
	} else {
		if (oauth2_jose_hash_bytes(log, passphrase_hash_algo,
					   (const unsigned char *)passphrase,
					   strlen(passphrase), &cache->enc_key,
					   &enc_key_len) == false) {
			oauth2_error(
			    log, "could not hash cache encryption passphrase");
			goto end;
		}
	}

end:

	if (cache)
		_oauth2_cache_register(
		    log, oauth2_nv_list_get(log, params, "name"), cache);

	if (passphrase)
		oauth2_mem_free(passphrase);

	return cache;
}

static void _oauth2_cache_free(oauth2_log_t *log, oauth2_cache_t *cache)
{
	if ((cache == NULL) || (cache->type == NULL))
		goto end;

	cache->refcount--;
	if (cache->refcount == 0) {

		if (cache->key_hash_algo)
			oauth2_mem_free(cache->key_hash_algo);
		if (cache->enc_key)
			oauth2_mem_free(cache->enc_key);

		if (cache->type->free)
			cache->type->free(log, cache);
		oauth2_mem_free(cache);
	}

end:

	return;
}

oauth2_cache_t *oauth2_cache_clone(oauth2_log_t *log, oauth2_cache_t *cache)
{
	if ((cache == NULL) || (cache->type == NULL))
		goto end;

	cache->refcount++;

end:

	return cache;
}

void _oauth2_cache_type_register(oauth2_cache_type_t *type)
{
	oauth2_cache_type_list_t *ptr = NULL, *prev = NULL;
	ptr = oauth2_mem_alloc(sizeof(oauth2_cache_type_list_t));
	ptr->type = type;
	ptr->next = NULL;
	if (_cache_types) {
		prev = _cache_types;
		while (prev->next)
			prev = prev->next;
		prev->next = ptr;
	} else {
		_cache_types = ptr;
	}
}

static void _oauth2_cache_register(oauth2_log_t *log, const char *name,
				   oauth2_cache_t *cache)
{
	oauth2_cache_list_t *ptr = NULL, *prev = NULL;

	oauth2_debug(log, "enter: %s", name);

	ptr = oauth2_mem_alloc(sizeof(oauth2_cache_list_t));
	ptr->name = oauth2_strdup(name);
	ptr->cache = cache;
	ptr->next = NULL;
	if (_cache_list) {
		prev = _cache_list;
		while (prev->next)
			prev = prev->next;
		prev->next = ptr;
	} else {
		_cache_list = ptr;
	}

	oauth2_debug(log, "leave");
}

oauth2_cache_t *_oauth2_cache_obtain(oauth2_log_t *log, const char *name)
{
	oauth2_cache_t *rv = NULL;
	oauth2_cache_list_t *ptr = NULL, *result = NULL;

	oauth2_debug(log, "enter: %s", name);

	if (_cache_list == NULL) {
		if (oauth2_cache_init(log, NULL, NULL) == NULL)
			goto end;
		if (oauth2_cache_post_config(log, _cache_list->cache) == false)
			goto end;
	}

	ptr = _cache_list;
	while (ptr) {
		if ((name) && (ptr->name)) {
			if (strcmp(ptr->name, name) == 0) {
				result = ptr;
				break;
			}
		} else if ((name == NULL) || (strcmp("default", name) == 0)) {
			result = ptr;
		}
		ptr = ptr->next;
	}

	rv = result ? oauth2_cache_clone(log, result->cache) : NULL;

end:

	oauth2_debug(log, "leave: %p", rv);

	return rv;
}

void oauth2_cache_release(oauth2_log_t *log, oauth2_cache_t *cache)
{
	oauth2_cache_list_t *ptr = NULL, *prev = NULL;
	oauth2_uint_t refcount = 0;

	oauth2_debug(log, "enter");

	if (cache == NULL)
		goto end;

	refcount = cache->refcount;
	_oauth2_cache_free(log, cache);

	if (refcount > 1)
		goto end;

	ptr = _cache_list;
	prev = NULL;
	while (ptr) {
		if (ptr->cache == cache) {
			if (prev)
				prev->next = ptr->next;
			else
				_cache_list = ptr->next;
			if (ptr->name)
				oauth2_mem_free(ptr->name);
			oauth2_mem_free(ptr);
			break;
		}
		prev = ptr;
		ptr = ptr->next;
	}

end:

	oauth2_debug(log, "return");

	return;
}

bool oauth2_cache_post_config(oauth2_log_t *log, oauth2_cache_t *cache)
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

static int oauth2_cache_decrypt(oauth2_log_t *log, oauth2_cache_t *cache,
				const char *value, unsigned char **plaintext);

bool oauth2_cache_get(oauth2_log_t *log, oauth2_cache_t *cache, const char *key,
		      char **value)
{
	bool rc = false;
	char *hashed_key = NULL;

	oauth2_debug(log, "enter: key=%s, type=%s, decrypt=%d", key,
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

	if ((cache->encrypt) && (*value))
		if (oauth2_cache_decrypt(log, cache, *value,
					 (unsigned char **)value) < 0)
			goto end;

	rc = true;

end:

	if (hashed_key)
		oauth2_mem_free(hashed_key);

	oauth2_debug(log, "leave: cache %s for key: %s return: %lu bytes",
		     rc ? (*value ? "hit" : "miss") : "error", key,
		     *value ? (unsigned long)strlen(*value) : 0);

	return rc;
}

static int oauth2_cache_encrypt(oauth2_log_t *log, oauth2_cache_t *cache,
				const char *plaintext, char **result);

bool oauth2_cache_set(oauth2_log_t *log, oauth2_cache_t *cache, const char *key,
		      const char *value, oauth2_time_t ttl_s)
{

	bool rc = false;
	char *hashed_key = NULL;
	char *encrypted = NULL;

	oauth2_debug(log,
		     "enter: key=%s, len=%lu, ttl(s)=" OAUTH2_TIME_T_FORMAT
		     ", type=%s, encrypt=%d",
		     key, value ? (unsigned long)strlen(value) : 0, ttl_s,
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
		oauth2_debug(log, "leave: successfully stored: %s", key);
	else
		oauth2_error(log, "leave: could NOT store: %s", key);

	return rc;
}

#define OAUTH2_CACHE_CIPHER EVP_aes_256_gcm()
#define OAUTH2_CACHE_TAG_LEN 16

#if (OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER))
#define OAUTH2_CACHE_CRYPTO_GET_TAG EVP_CTRL_AEAD_GET_TAG
#define OAUTH2_CACHE_CRYPTO_SET_TAG EVP_CTRL_AEAD_SET_TAG
#define OAUTH2_CACHE_CRYPTO_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN
#else
#define OAUTH2_CACHE_CRYPTO_GET_TAG EVP_CTRL_GCM_GET_TAG
#define OAUTH2_CACHE_CRYPTO_SET_TAG EVP_CTRL_GCM_SET_TAG
#define OAUTH2_CACHE_CRYPTO_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN
#endif

static const unsigned char OAUTH2_CACHE_CRYPTO_GCM_AAD[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde};
static const unsigned char OAUTH2_CACHE_CRYPTO_GCM_IV[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// TODO: static encryption/decryption context?

static int _oauth2_cache_encrypt_impl(oauth2_log_t *log, oauth2_cache_t *cache,
				      unsigned char *plaintext,
				      int plaintext_len,
				      const unsigned char *aad, int aad_len,
				      const unsigned char *iv, int iv_len,
				      unsigned char *ciphertext,
				      const unsigned char *tag, int tag_len)
{

	int ciphertext_len = 0;
	int len = -1;
	EVP_CIPHER_CTX *ctx = NULL;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		oauth2_error(log, "EVP_CIPHER_CTX_new failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_EncryptInit_ex(ctx, OAUTH2_CACHE_CIPHER, NULL, NULL, NULL)) {
		oauth2_error(log, "EVP_EncryptInit_ex failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, OAUTH2_CACHE_CRYPTO_SET_IVLEN, iv_len,
				 NULL)) {
		oauth2_error(log, "EVP_CIPHER_CTX_ctrl failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, cache->enc_key, iv)) {
		oauth2_error(log, "EVP_EncryptInit_ex failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		oauth2_error(log, "EVP_EncryptUpdate aad failed aad_len=%d: %s",
			     aad_len, _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
			       plaintext_len)) {
		oauth2_error(log, "EVP_EncryptUpdate ciphertext failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}
	ciphertext_len = len;

	if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		oauth2_error(log, "EVP_EncryptFinal_ex failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}
	ciphertext_len += len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, OAUTH2_CACHE_CRYPTO_GET_TAG, tag_len,
				 (void *)tag)) {
		oauth2_error(log, "EVP_CIPHER_CTX_ctrl failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

end:

	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static int oauth2_cache_encrypt(oauth2_log_t *log, oauth2_cache_t *cache,
				const char *plaintext, char **result)
{
	int ciphertext_len = -1;
	size_t len = -1;
	uint8_t *buf = NULL;

	oauth2_debug(log, "enter: %s", plaintext);

	len = strlen(plaintext);
	buf = oauth2_mem_alloc(OAUTH2_CACHE_TAG_LEN + len +
			       EVP_CIPHER_block_size(OAUTH2_CACHE_CIPHER));
	if (buf == NULL)
		goto end;

	ciphertext_len = _oauth2_cache_encrypt_impl(
	    log, cache, (unsigned char *)plaintext, len,
	    OAUTH2_CACHE_CRYPTO_GCM_AAD, sizeof(OAUTH2_CACHE_CRYPTO_GCM_AAD),
	    OAUTH2_CACHE_CRYPTO_GCM_IV, sizeof(OAUTH2_CACHE_CRYPTO_GCM_IV),
	    buf + OAUTH2_CACHE_TAG_LEN, buf, OAUTH2_CACHE_TAG_LEN);

	len = oauth2_base64_encode(
	    log, buf, OAUTH2_CACHE_TAG_LEN + ciphertext_len, result);

end:

	if (buf)
		oauth2_mem_free(buf);

	oauth2_debug(log, "leave: len=%d", (int)len);

	return len;
}

static int _oauth2_cache_decrypt_impl(oauth2_log_t *log, oauth2_cache_t *cache,
				      unsigned char *ciphertext,
				      int ciphertext_len,
				      const unsigned char *aad, int aad_len,
				      const unsigned char *tag, int tag_len,
				      const unsigned char *iv, int iv_len,
				      unsigned char *plaintext)
{

	int plaintext_len = -1;
	int len = 0;
	EVP_CIPHER_CTX *ctx = NULL;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		oauth2_error(log, "EVP_CIPHER_CTX_new failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_DecryptInit_ex(ctx, OAUTH2_CACHE_CIPHER, NULL, NULL, NULL)) {
		oauth2_error(log, "EVP_DecryptInit_ex failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, OAUTH2_CACHE_CRYPTO_SET_IVLEN, iv_len,
				 NULL)) {
		oauth2_error(log, "EVP_CIPHER_CTX_ctrl failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, cache->enc_key, iv)) {
		oauth2_error(log, "EVP_DecryptInit_ex failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		oauth2_error(log, "EVP_DecryptUpdate aad failed aad_len=%d: %s",
			     aad_len, _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
			       ciphertext_len)) {
		oauth2_error(log, "EVP_DecryptUpdate ciphertext failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}
	plaintext_len = len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, OAUTH2_CACHE_CRYPTO_SET_TAG, tag_len,
				 (void *)tag)) {
		oauth2_error(log, "EVP_CIPHER_CTX_ctrl failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}

	if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		oauth2_error(log, "EVP_DecryptFinal_ex failed: %s",
			     _OAUTH2_CACHE_OPENSSL_ERR);
		goto end;
	}
	plaintext_len += len;

end:

	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

static int oauth2_cache_decrypt(oauth2_log_t *log, oauth2_cache_t *cache,
				const char *value, unsigned char **plaintext)
{
	int len = -1;
	uint8_t *buf = NULL;
	size_t buf_len = -1;
	unsigned char *rv = NULL;

	oauth2_debug(log, "enter");

	if (oauth2_base64_decode(log, value, &buf, &buf_len) == false)
		goto end;

	len = buf_len - OAUTH2_CACHE_TAG_LEN;
	rv = oauth2_mem_alloc(len + EVP_CIPHER_block_size(OAUTH2_CACHE_CIPHER));

	len = _oauth2_cache_decrypt_impl(
	    log, cache, (unsigned char *)(buf + OAUTH2_CACHE_TAG_LEN), len,
	    OAUTH2_CACHE_CRYPTO_GCM_AAD, sizeof(OAUTH2_CACHE_CRYPTO_GCM_AAD),
	    (unsigned char *)buf, OAUTH2_CACHE_TAG_LEN,
	    OAUTH2_CACHE_CRYPTO_GCM_IV, sizeof(OAUTH2_CACHE_CRYPTO_GCM_IV), rv);

	if (len <= 0) {
		oauth2_mem_free(rv);
		goto end;
	}

	rv[len] = '\0';

	// because we passed in the value buffer itself to avoid memory copies
	if (*plaintext)
		oauth2_mem_free(*plaintext);
	*plaintext = rv;

end:

	if (buf)
		oauth2_mem_free(buf);

	oauth2_debug(log, "leave: len=%d", len);

	return len;
}
