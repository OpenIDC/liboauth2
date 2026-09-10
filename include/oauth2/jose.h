#ifndef _OAUTH2_JOSE_H_
#define _OAUTH2_JOSE_H_

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
 * @file jose.h
 * @brief JWT, JWK and JWKS handling on top of cjose.
 *
 * The JOSE layer of the library: hashing and symmetric key derivation
 * (OpenSSL), authenticated encryption of strings and JSON objects
 * under a shared secret (JWS inside JWE, used for the state cookies of
 * the OpenID Connect RP flow, "cookie" type sessions and encrypted
 * cache entries), signed JWT creation (client assertions for the
 * private_key_jwt and client_secret_jwt endpoint authentication
 * methods in cfg.h) and signed JWT verification against a set of keys
 * (the "jwk", "jwks_uri", "eckey_uri", "aws_alb" etc. verification
 * methods of oauth2_token_verify() in oauth2.h, id_token verification
 * in openidc.h and DPoP proofs in src/dpop.c).
 *
 * The cjose allocator is wired to the oauth2_mem_* functions (mem.h),
 * so any string returned here is released with oauth2_mem_free().
 */

#include <cjose/cjose.h>
#include <jansson.h>

#include "oauth2/cfg.h"
#include "oauth2/log.h"
#include "oauth2/util.h"

/**
 * @name Digest algorithm names
 * OpenSSL digest names accepted by the hashing functions and by the
 * hash_algo parameter of oauth2_jose_jwk_create_symmetric(); any name
 * EVP_get_digestbyname() knows is accepted, these are the ones the
 * library uses itself.
 * @{
 */
#define OAUTH2_JOSE_OPENSSL_ALG_SHA1 "sha1"
#define OAUTH2_JOSE_OPENSSL_ALG_SHA256 "sha256"
/** @} */

/**
 * @name JOSE header and JWT claim names
 * The "typ" header (RFC 7515 section 4.1.9) and the registered claim
 * names of RFC 7519 section 4.1 as used in JWT verification.
 * @{
 */
#define OAUTH2_JOSE_HDR_TYP "typ"
#define OAUTH2_JOSE_HDR_TYP_JWT "JWT"

#define OAUTH2_JOSE_JWT_ISS "iss"
#define OAUTH2_JOSE_JWT_IAT "iat"
#define OAUTH2_JOSE_JWT_EXP "exp"
#define OAUTH2_JOSE_JWT_NBF "nbf"
#define OAUTH2_JOSE_JWT_SUB "sub"
#define OAUTH2_JOSE_JWT_AUD "aud"
/** @} */

/**
 * @name Keys
 * A JWK as the library handles it: a cjose_jwk_t together with its
 * "kid", and a linked list of those as resolved from a JWKS. Lists are
 * created and consumed by the JWT verification machinery; the only
 * public operations are releasing them.
 * @{
 */

typedef struct oauth2_jose_jwk_t oauth2_jose_jwk_t;

/**
 * @brief Release a key, including the cjose_jwk_t it wraps.
 *
 * @param jwk the key to release, obtained from
 *            oauth2_jose_jwk_create_symmetric()
 */
void oauth2_jose_jwk_release(oauth2_jose_jwk_t *jwk);

typedef struct oauth2_jose_jwk_list_t oauth2_jose_jwk_list_t;

/**
 * @brief Release a list of keys and every key in it.
 *
 * @param log  the log handle to use
 * @param keys the head of the list; NULL is accepted
 */
void oauth2_jose_jwk_list_free(oauth2_log_t *log, oauth2_jose_jwk_list_t *keys);
/** @} */

/**
 * @name Hashing
 * @{
 */

/**
 * @brief Hash a byte string with an OpenSSL digest.
 *
 * @param log     the log handle to use
 * @param digest  the OpenSSL digest name, e.g.
 *                OAUTH2_JOSE_OPENSSL_ALG_SHA256
 * @param src     the bytes to hash; hashing an empty input fails
 * @param src_len the number of bytes in src
 * @param dst     set to the raw (binary, not encoded) digest as a
 *                newly allocated buffer, to be released with
 *                oauth2_mem_free()
 * @param dst_len set to the number of bytes in dst
 * @return true on success, false when the digest is unknown, the
 *         input is empty or hashing failed
 */
bool oauth2_jose_hash_bytes(oauth2_log_t *log, const char *digest,
			    const unsigned char *src, unsigned int src_len,
			    unsigned char **dst, unsigned int *dst_len);

/**
 * @brief Hash a string and return the digest as a hex string.
 *
 * Hashes src with oauth2_jose_hash_bytes() and lowercase-hex encodes
 * the result, e.g. 64 characters for "sha256"; used to derive cache
 * keys and cache encryption keys from their plaintext.
 *
 * @param log    the log handle to use
 * @param digest the OpenSSL digest name
 * @param src    the NUL-terminated string to hash, must not be NULL
 * @param dst    set to the hex-encoded digest as a newly allocated
 *               string, to be released with oauth2_mem_free()
 * @return true on success, false on error
 */
bool oauth2_jose_hash2s(oauth2_log_t *log, const char *digest, const char *src,
			char **dst);
/** @} */

/**
 * @name Symmetric keys
 * @{
 */

/**
 * @brief Derive a symmetric ("oct") JWK from a secret.
 *
 * @param log           the log handle to use
 * @param client_secret the secret to derive the key from
 * @param hash_algo     the OpenSSL digest to hash the secret with, the
 *                      digest becoming the key material (the OpenID
 *                      Connect Core 1.0 section 10.1 way of turning a
 *                      client_secret into a key); NULL uses the bytes
 *                      of the secret as the key as-is
 * @param jwk           set to the new key, to be released with
 *                      oauth2_jose_jwk_release()
 * @return true on success, false on error
 */
bool oauth2_jose_jwk_create_symmetric(oauth2_log_t *log,
				      const char *client_secret,
				      const char *hash_algo,
				      oauth2_jose_jwk_t **jwk);
/** @} */

/**
 * @name Encryption under a shared secret
 * Authenticated encryption of a payload under a passphrase: the key is
 * the SHA-256 digest of the secret (oauth2_jose_jwk_create_symmetric()
 * with OAUTH2_JOSE_OPENSSL_ALG_SHA256), the payload is first signed
 * into a compact JWS with HS256 and that JWS is then encrypted into a
 * compact JWE with "alg":"dir" and "enc":"A256GCM". Decryption
 * reverses both steps and fails when either the JWE cannot be
 * decrypted or the inner signature does not verify under the same
 * secret.
 * @{
 */

/**
 * @brief Encrypt a string under a shared secret.
 *
 * @param log           the log handle to use
 * @param secret        the shared secret
 * @param s_sig_payload the string to sign and encrypt
 * @param cser          set to the compact serialized JWE as a newly
 *                      allocated string, to be released with
 *                      oauth2_mem_free()
 * @return true on success, false on error
 */
bool oauth2_jose_encrypt(oauth2_log_t *log, const char *secret,
			 const char *s_sig_payload, char **cser);

/**
 * @brief Encrypt a JSON object under a shared secret.
 *
 * The compact JSON serialization of payload is encrypted with
 * oauth2_jose_encrypt().
 *
 * @param log     the log handle to use
 * @param secret  the shared secret
 * @param payload the JSON object to sign and encrypt
 * @param cser    set to the compact serialized JWE as a newly
 *                allocated string, to be released with
 *                oauth2_mem_free()
 * @return true on success, false on error
 */
bool oauth2_jose_jwt_encrypt(oauth2_log_t *log, const char *secret,
			     json_t *payload, char **cser);

/**
 * @brief Decrypt a string encrypted with oauth2_jose_encrypt().
 *
 * @param log    the log handle to use
 * @param secret the shared secret the string was encrypted under
 * @param cser   the compact serialized JWE
 * @param result set to the plaintext as a newly allocated
 *               NUL-terminated string, to be released with
 *               oauth2_mem_free()
 * @return true on success, false when decryption or the inner
 *         signature verification failed
 */
bool oauth2_jose_decrypt(oauth2_log_t *log, const char *secret,
			 const char *cser, char **result);

/**
 * @brief Decrypt a JSON object encrypted with oauth2_jose_jwt_encrypt().
 *
 * @param log    the log handle to use
 * @param secret the shared secret the object was encrypted under
 * @param cser   the compact serialized JWE
 * @param result set to the decrypted payload parsed into a new JSON
 *               value, to be released with json_decref()
 * @return true on success, false when decryption, signature
 *         verification or JSON parsing failed
 */
bool oauth2_jose_jwt_decrypt(oauth2_log_t *log, const char *secret,
			     const char *cser, json_t **result);
/** @} */

/**
 * @name JWT verification
 * @{
 */

/**
 * @brief The keys and claim validation settings a JWT is verified with.
 *
 * Created and owned by the "jwk", "jwks_uri", "eckey_uri", "aws_alb"
 * etc. verification methods of a token verification chain, i.e.
 * populated from the options passed to
 * oauth2_cfg_token_verify_add_options() in cfg.h: the key source, the
 * expected "iss" and "aud" values, the "verify.iss", "verify.aud",
 * "verify.exp", "verify.nbf" and "verify.iat" strictness options
 * (each "required", "optional" or "skip") and the
 * "verify.iat.slack_before" and "verify.iat.slack_after" allowances
 * in seconds.
 */
typedef struct oauth2_jose_jwt_verify_ctx_t oauth2_jose_jwt_verify_ctx_t;

/**
 * @brief Verify the signature and claims of a compact serialized JWS.
 *
 * Resolves the verification keys from the context's key source
 * (re-resolving once from a remote source when no key verified the
 * signature and the source allows a refresh), tries every key whose
 * "kid" matches the JWS header - keys without a "kid" and tokens
 * without one are tried against everything - and, once a key verified
 * the signature, parses the payload as a JSON object and validates its
 * "iss", "aud", "exp", "nbf" and "iat" claims per the context's
 * settings: a "required" claim must be present and valid, an
 * "optional" one is validated only when present, a "skip"ped one is
 * ignored; "iss"/"aud" are compared to the expected values ("aud" may
 * be a string or an array of strings), "exp" and "nbf" against the
 * current time and "iat" against the slack settings.
 *
 * @param log            the log handle to use
 * @param jwt_verify_ctx the keys and claim validation settings; NULL
 *                       skips the signature verification and the
 *                       claim validation altogether and only extracts
 *                       the payload, so a NULL context must never be
 *                       used to accept a token
 * @param token          the compact serialized JWS
 * @param json_payload   set to the verified payload as a new JSON
 *                       object, to be released with json_decref();
 *                       must not be NULL
 * @param s_payload      set to the verified payload as a newly
 *                       allocated string, to be released with
 *                       oauth2_mem_free(); must not be NULL
 * @return true when the signature verified and the claims validated,
 *         false otherwise (both outputs are then left unset)
 */
bool oauth2_jose_jwt_verify(oauth2_log_t *log,
			    oauth2_jose_jwt_verify_ctx_t *jwt_verify_ctx,
			    const char *token, json_t **json_payload,
			    char **s_payload);
/** @} */

/**
 * @name JWK thumbprint
 * @{
 */

/**
 * @brief Compute the SHA-256 JWK thumbprint of a key (RFC 7638).
 *
 * Builds the canonical JSON representation of the required members of
 * the key ("crv", "kty", "x", "y" for EC, "e", "kty", "n" for RSA,
 * "k", "kty" for oct keys, in lexicographic order, no whitespace) and
 * hashes it with SHA-256; a DPoP "jkt" confirmation claim is the
 * base64url encoding of the result.
 *
 * @param log            the log handle to use
 * @param jwk            the key to compute the thumbprint of
 * @param hash_bytes     set to the raw 32-byte digest as a newly
 *                       allocated buffer, to be released with
 *                       oauth2_mem_free()
 * @param hash_bytes_len set to the number of bytes in hash_bytes
 * @return true on success, false when the key type is not EC, RSA or
 *         oct or hashing failed
 */
bool oauth2_jose_jwk_thumbprint(oauth2_log_t *log, const cjose_jwk_t *jwk,
				unsigned char **hash_bytes,
				unsigned int *hash_bytes_len);
/** @} */

/**
 * @name JWT creation
 * @{
 */

/**
 * @brief Create a signed JWT.
 *
 * Signs a JSON payload into a compact serialized JWS with the header
 * {"alg":alg,"typ":"JWT"}. The payload starts as a deep copy of
 * json_payload (or an empty object) into which the claims given as
 * parameters are set, overriding same-named members of json_payload.
 * This is what the private_key_jwt and client_secret_jwt endpoint
 * authentication methods use to create their client assertion.
 *
 * @param log          the log handle to use
 * @param jwk          the cjose key to sign with; must match alg
 * @param alg          the JWS "alg" to sign with, e.g. "RS256" or
 *                     "HS256"
 * @param iss          the "iss" claim, or NULL to leave it out
 * @param sub          the "sub" claim, or NULL to leave it out
 * @param client_id    unused
 * @param aud          the "aud" claim, or NULL to leave it out
 * @param exp          the lifetime of the JWT in seconds, the "exp"
 *                     claim being set to that many seconds from now;
 *                     0 leaves "exp" out
 * @param include_iat  set the "iat" claim to the current time
 * @param include_jti  set the "jti" claim to a random string
 * @param json_payload additional claims to start from, or NULL
 * @return the compact serialized JWS as a newly allocated string, to
 *         be released with oauth2_mem_free(), or NULL on error
 */
char *oauth2_jwt_create(oauth2_log_t *log, cjose_jwk_t *jwk, const char *alg,
			const char *iss, const char *sub, const char *client_id,
			const char *aud, oauth2_uint_t exp, bool include_iat,
			bool include_jti, const json_t *json_payload);
/** @} */

#endif /* _OAUTH2_JOSE_H_ */
