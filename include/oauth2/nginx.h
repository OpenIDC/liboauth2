#ifndef _OAUTH2_NGINX_H_
#define _OAUTH2_NGINX_H_

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
 * @file nginx.h
 * @brief The NGINX binding of the library (liboauth2_nginx).
 *
 * The glue that NGINX modules built on this library - ngx_oauth2_module,
 * ngx_sts_module - use to plug the server-agnostic core into NGINX. It
 * maps an ngx_http_request_t onto the oauth2_http_request_t /
 * oauth2_http_response_t abstraction (http.h) and the NGINX error log
 * onto an oauth2_log_sink_t (log.h), publishes the claims of a
 * verified token as NGINX variables and evaluates "require"
 * expressions against them, and provides macros that generate the
 * module table, the directive handlers and the ngx_command_t entries
 * a module needs.
 *
 * The macros assume the module's naming scheme: for a module named
 * "foo" the NGINX module object is `ngx_foo_module` and the directive
 * handlers are `ngx_foo_set_<primitive>`; the per-location
 * configuration struct they operate on must have an "oauth2_log_t *log"
 * member.
 */

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_request.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oauth2/http.h>
#include <oauth2/log.h>
#include <oauth2/util.h>

/**
 * @name Module table
 * @{
 */

/**
 * @brief Generate the module table of a dynamic module.
 *
 * Defines the ngx_modules, ngx_module_names and ngx_module_order arrays
 * that NGINX's build system would otherwise generate in
 * `objs/ngx_<module>_module_modules.c`, listing the single module
 * `ngx_<module>_module` (declared extern by the macro), so that the
 * module can be built as a shared object outside of the NGINX build
 * tree. Use it in a source file of its own, e.g.
 * OAUTH2_NGINX_MODULE(oauth2) in ngx_oauth2_module_modules.c.
 */
#define OAUTH2_NGINX_MODULE(module)                                            \
	extern ngx_module_t ngx_##module##_module;                             \
                                                                               \
	ngx_module_t *ngx_modules[] = {&ngx_##module##_module, NULL};          \
                                                                               \
	char *ngx_module_names[] = {OAUTH2_TOSTRING(ngx_##module##_module),    \
				    NULL};                                     \
                                                                               \
	char *ngx_module_order[] = {NULL};
/** @} */

/**
 * @name Directive handlers
 * Macros generating the ngx_command_t "set" handler
 * `ngx_<module>_set_<primitive>()` of a directive - with the
 * (ngx_conf_t *cf, ngx_command_t *cmd, void *conf) signature -
 * referenced by name from OAUTH2_NGINX_CMD(). The ARGS variants
 * forward the directive's
 * arguments to a config setter of the library with the "return NULL on
 * success, an error string on failure" convention (cfg.h), the RET1
 * variant to a setter operating on a member of the location config.
 * @{
 */

/**
 * @brief Open a hand-written directive handler.
 *
 * Starts the definition of `ngx_<module>_set_<primitive>()` and declares
 * three locals for the body that follows: "rv" (const char *, the
 * error string to return, initially NULL), "cfg" (the location config
 * conf cast to type *) and "value" (the ngx_str_t array of the
 * directive's arguments, value[0] being the directive name and
 * cf->args->nelts its length). Close the handler with
 * OAUTH2_NGINX_CFG_FUNC_END().
 */
#define OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	static char *ngx_##module##_set_##primitive(                           \
	    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)                    \
	{                                                                      \
		const char *rv = NULL;                                         \
		type *cfg = (type *)conf;                                      \
		ngx_str_t *value = cf->args->elts;
// fprintf(stderr, " ## %s: %p (log=%p)\n", __FUNCTION__, cfg, cf->log);

/**
 * @brief Close a directive handler opened with
 *        OAUTH2_NGINX_CFG_FUNC_START().
 *
 * Logs rv at NGX_LOG_ERR to the configuration log when it is set and
 * returns NGX_CONF_ERROR then, NGX_CONF_OK otherwise.
 */
#define OAUTH2_NGINX_CFG_FUNC_END(cf, rv)                                      \
	if (rv)                                                                \
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, rv);                    \
	return rv ? NGX_CONF_ERROR : NGX_CONF_OK;                              \
	}

/**
 * @brief Generate a directive handler calling func(cf, &cfg->member).
 *
 * For setters that parse the directive's arguments from the ngx_conf_t
 * themselves and store into a member of the location config, e.g.
 * nginx_oauth2_set_require() with an ngx_array_t * member.
 */
#define OAUTH2_NGINX_CFG_FUNC_RET1(module, type, primitive, func, member)      \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	(void)value;                                                           \
	rv = func(cf, &cfg->member);                                           \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

/**
 * @brief Generate a directive handler calling func(cfg->log, member,
 *        v1) with the directive's first argument.
 *
 * The argument is copied into a NUL-terminated string that is released
 * after the call; an absent argument is passed as NULL. "member" is any
 * expression evaluated inside the handler, typically the address of
 * the config member to set or NULL for global setters such as
 * oauth2_crypto_passphrase_set().
 */
#define OAUTH2_NGINX_CFG_FUNC_ARGS1(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1);                                       \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

/**
 * @brief Generate a directive handler calling func(cfg->log, member,
 *        v1, v2) with the directive's first two arguments.
 *
 * See OAUTH2_NGINX_CFG_FUNC_ARGS1(); e.g. oauth2_cfg_set_cache() for a
 * "<directive> <type> <options>" cache directive.
 */
#define OAUTH2_NGINX_CFG_FUNC_ARGS2(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	char *v2 = cf->args->nelts > 2                                         \
		       ? oauth2_strndup((const char *)value[2].data,           \
					(size_t)value[2].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1, v2);                                   \
	oauth2_mem_free(v2);                                                   \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

/**
 * @brief Generate a directive handler calling func(cfg->log, member,
 *        v1, v2, v3) with the directive's first three arguments.
 *
 * See OAUTH2_NGINX_CFG_FUNC_ARGS1().
 */
#define OAUTH2_NGINX_CFG_FUNC_ARGS3(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	char *v2 = cf->args->nelts > 2                                         \
		       ? oauth2_strndup((const char *)value[2].data,           \
					(size_t)value[2].len)                  \
		       : NULL;                                                 \
	char *v3 = cf->args->nelts > 3                                         \
		       ? oauth2_strndup((const char *)value[3].data,           \
					(size_t)value[3].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1, v2, v3);                               \
	oauth2_mem_free(v3);                                                   \
	oauth2_mem_free(v2);                                                   \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

/**
 * @brief Generate a directive handler calling func(cfg->log, member,
 *        v1, v2, v3, v4) with the directive's first four arguments.
 *
 * See OAUTH2_NGINX_CFG_FUNC_ARGS1().
 */
#define OAUTH2_NGINX_CFG_FUNC_ARGS4(module, type, primitive, func, member)     \
	OAUTH2_NGINX_CFG_FUNC_START(module, type, primitive)                   \
	char *v1 = cf->args->nelts > 1                                         \
		       ? oauth2_strndup((const char *)value[1].data,           \
					(size_t)value[1].len)                  \
		       : NULL;                                                 \
	char *v2 = cf->args->nelts > 2                                         \
		       ? oauth2_strndup((const char *)value[2].data,           \
					(size_t)value[2].len)                  \
		       : NULL;                                                 \
	char *v3 = cf->args->nelts > 3                                         \
		       ? oauth2_strndup((const char *)value[3].data,           \
					(size_t)value[3].len)                  \
		       : NULL;                                                 \
	char *v4 = cf->args->nelts > 4                                         \
		       ? oauth2_strndup((const char *)value[3].data,           \
					(size_t)value[4].len)                  \
		       : NULL;                                                 \
	rv = func(cfg->log, member, v1, v2, v3, v4);                           \
	oauth2_mem_free(v4);                                                   \
	oauth2_mem_free(v3);                                                   \
	oauth2_mem_free(v2);                                                   \
	oauth2_mem_free(v1);                                                   \
	OAUTH2_NGINX_CFG_FUNC_END(cf, rv)
/** @} */

/**
 * @name Commands
 * @{
 */

/**
 * @brief Generate an ngx_command_t entry for a directive.
 *
 * Declares the directive as allowed in location and if-in-location
 * context, handled by `ngx_<module>_set_<primitive>()` (generated with
 * the OAUTH2_NGINX_CFG_FUNC_* macros or OAUTH2_NGINX_CMD_SET_IMPL())
 * on the module's location config. "take" is the digits appended to
 * NGX_CONF_TAKE to express the accepted argument counts - 1, 12, 123,
 * ... - and may be OR-ed with further NGX_CONF_TAKE<n> flags for
 * counts beyond 3, e.g. OAUTH2_NGINX_CMD(3 | NGX_CONF_TAKE4, oauth2,
 * "OAuth2TokenVerify", token_verify).
 */
// clang-format off
#define OAUTH2_NGINX_CMD(take, module, directive, primitive)                   \
	{                                                                      \
		ngx_string(directive),                                         \
		    NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF |                    \
			NGX_CONF_TAKE##take,                                   \
		    ngx_##module##_set_##primitive, NGX_HTTP_LOC_CONF_OFFSET,  \
		    0, NULL                                                    \
	}
// clang-format on
/** @} */

/**
 * @name Logging
 * @{
 */

/**
 * @brief The log sink callback writing to the NGINX error log.
 *
 * An oauth2_log_function_t for oauth2_log_sink_create() whose sink
 * context is the ngx_log_t to write to; the request context created by
 * oauth2_nginx_request_context_init() installs it on the request's
 * connection log. Messages are written as "# <function>: <msg>" at the
 * NGINX level the library level maps to: error, warn, notice, info and
 * debug map to their namesakes, trace1 to debug as well and trace2 to
 * stderr.
 */
void oauth2_nginx_log(oauth2_log_sink_t *sink, const char *filename,
		      unsigned long line, const char *function,
		      oauth2_log_level_t level, const char *msg);
/** @} */

/**
 * @name Request context
 * @{
 */

/**
 * @brief The per-request state of a module: the log handle, the NGINX
 *        request and its translation into the library's request type.
 */
typedef struct oauth2_nginx_request_context_t {
	oauth2_log_t *log;
	ngx_http_request_t *r;
	oauth2_http_request_t *request;
} oauth2_nginx_request_context_t;

/**
 * @brief Create the request context for an NGINX request.
 *
 * Creates a log handle at trace1 level with an oauth2_nginx_log() sink
 * on the request's connection log, and an oauth2_http_request_t
 * populated from the request: the scheme ("https" when the connection
 * is TLS), the hostname and port of the local address (0 for a Unix
 * domain socket), the path, query string and method (GET, POST, PUT,
 * DELETE, CONNECT or OPTIONS, anything else is "unknown") and all
 * request headers. When the $ssl_client_cert variable is set, its
 * value is stored in the request's context under
 * OAUTH2_TLS_CERT_VAR_NAME so that mTLS-bound tokens can be verified.
 *
 * @param r the NGINX request
 * @return the new request context, to be released by the caller with
 *         oauth2_nginx_request_context_free() when the request has
 *         been handled
 */
oauth2_nginx_request_context_t *
oauth2_nginx_request_context_init(ngx_http_request_t *r);

/**
 * @brief Release a request context: its request translation, its log
 *        handle and sink, and the context itself.
 *
 * @param rec the oauth2_nginx_request_context_t to release, typed as
 *            void * so that it can serve as a pool cleanup handler;
 *            NULL is accepted
 */
void oauth2_nginx_request_context_free(void *rec);

/**
 * @brief Apply a library response to an NGINX request.
 *
 * Appends every header of the response - Set-Cookie headers from
 * oauth2_http_response_cookie_set() included - to the request's
 * headers_out and sets its status; the headers are not sent and the
 * response body is not applied, that is left to the caller.
 *
 * @param log      the log handle to use
 * @param response the response to apply
 * @param r        the NGINX request to apply it to
 * @return the ngx_int_t for the caller's handler to return: NGX_OK for
 *         a 200 status, NGX_HTTP_MOVED_TEMPORARILY for 302,
 *         NGX_HTTP_UNAUTHORIZED for 401 and the status code itself for
 *         anything else; NGX_ERROR when response or r is NULL
 */
ngx_int_t oauth2_nginx_http_response_set(oauth2_log_t *log,
					 oauth2_http_response_t *response,
					 ngx_http_request_t *r);
/** @} */

/**
 * @name Claims as variables
 * A module publishes the claims of a verified token as NGINX variables
 * in two steps: at configuration time a "<directive> <claim>
 * $<variable>" directive (handled by oauth2_nginx_set_claim(), e.g.
 * "OAuth2Claim sub $oauth2_sub") registers the variable with
 * oauth2_nginx_claim_variable() as its get handler, and at request
 * time the module stores the token's claims with
 * oauth2_nginx_set_target_variables() after which the variables
 * resolve to them - for use in proxy_set_header, map, if, etc. The
 * claims are kept in a hash in the request pool, registered as the
 * module's request context (ngx_http_set_ctx()).
 * @{
 */

/**
 * @brief Copy an ngx_str_t into a NUL-terminated string.
 *
 * @param p   the pool to allocate from
 * @param str the string to copy
 * @return the copy, or NULL when the allocation failed
 */
char *oauth2_nginx_str2chr(ngx_pool_t *p, const ngx_str_t *str);

/**
 * @brief Generate the variable get handler and directive handler of a
 *        claims-to-variables directive for a module.
 *
 * Defines `ngx_<module>_<primitive>_variable()` and
 * `ngx_<module>_set_<primitive>()` forwarding to
 * `oauth2_nginx_<primitive>_variable()` resp.
 * `oauth2_nginx_set_<primitive>()` with the module's
 * `ngx_<module>_module` (which must be declared before the macro is
 * used) filled in; with "claim" as the primitive those are
 * oauth2_nginx_claim_variable() and oauth2_nginx_set_claim().
 * Pair it with `OAUTH2_NGINX_CMD(2, <module>, "<directive>", claim)`.
 */
#define OAUTH2_NGINX_CMD_SET_IMPL(module, primitive)                           \
	static ngx_int_t ngx_##module##_##primitive##_variable(                \
	    ngx_http_request_t *r, ngx_http_variable_value_t *v,               \
	    uintptr_t data)                                                    \
	{                                                                      \
		return oauth2_nginx_##primitive##_variable(                    \
		    ngx_##module##_module, r, v, data);                        \
	}                                                                      \
                                                                               \
	static char *ngx_##module##_set_##primitive(                           \
	    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)                    \
	{                                                                      \
		return oauth2_nginx_set_##primitive(                           \
		    ngx_##module##_module,                                     \
		    ngx_##module##_##primitive##_variable, cf, cmd, conf);     \
	}

/**
 * @brief The get handler of a claim variable.
 *
 * Looks the claim up in the claims hash that
 * oauth2_nginx_set_target_variables() stored as the module's request
 * context; the variable is marked not found when no claims were stored
 * on this request or the claim is absent, and not cacheable otherwise.
 *
 * @param module the module owning the request context
 * @param r      the NGINX request
 * @param v      the variable value to fill in
 * @param data   the claim name, as set by oauth2_nginx_set_claim()
 * @return always NGX_OK
 */
ngx_int_t oauth2_nginx_claim_variable(ngx_module_t module,
				      ngx_http_request_t *r,
				      ngx_http_variable_value_t *v,
				      uintptr_t data);

/**
 * @brief Handle a "<directive> <claim> $<variable>" directive.
 *
 * Registers the variable (the second argument, which must start with
 * a "$") as a changeable NGINX variable with handler as its get handler
 * and the claim name (the first argument) as its data.
 *
 * @param module  the module the directive belongs to (unused)
 * @param handler the get handler to register, the one generated by
 *                OAUTH2_NGINX_CMD_SET_IMPL()
 * @param cf      the configuration being parsed
 * @param cmd     the directive being handled
 * @param conf    the location config (unused)
 * @return NGX_CONF_OK, or an error message allocated from the
 *         configuration pool (NGX_CONF_ERROR when even that fails)
 *         when the variable name is invalid or registering it failed
 */
char *oauth2_nginx_set_claim(ngx_module_t module,
			     ngx_http_get_variable_pt handler, ngx_conf_t *cf,
			     ngx_command_t *cmd, void *conf);

/**
 * @brief Store the claims of a token for the claim variables.
 *
 * Builds a hash of the members of json_token in the request pool -
 * string values as-is, any other value as its compact JSON encoding -
 * and registers it as the module's request context, so that the
 * variables registered with oauth2_nginx_set_claim() resolve for the
 * remainder of the request. Every key must be stored once: adding a
 * key that is already in the hash fails.
 *
 * @param module     the module to register the claims under
 * @param ctx        the request context
 * @param json_token the JSON object with the claims
 * @return NGX_OK on success, NGX_ERROR or the ngx_hash error code on
 *         failure (which is logged)
 */
ngx_int_t oauth2_nginx_set_target_variables(ngx_module_t module,
					    oauth2_nginx_request_context_t *ctx,
					    json_t *json_token);
/** @} */

/**
 * @name Authorization requirements
 * Authorization expressed in NGINX terms: a "require" directive lists
 * expressions with variables, typically claim variables or the result
 * of a "map" over them, and access is granted when each of them
 * evaluates to "1" on the request. E.g.:
 *
 *   map $oauth2_sub $valid_sub { default 0; "~^user" 1; }
 *   ...
 *   OAuth2Claim sub $oauth2_sub;
 *   OAuth2Require $valid_sub;
 * @{
 */

/**
 * @brief Handle a "<directive> <expression>..." require directive.
 *
 * Compiles each argument as an NGINX complex value (a string with
 * variables, ngx_http_compile_complex_value()) and appends it to the
 * requirements array, created in the configuration pool on first use.
 * Meant as the func of OAUTH2_NGINX_CFG_FUNC_RET1() with an
 * "ngx_array_t *" member of the location config.
 *
 * @param cf           the configuration being parsed
 * @param requirements the array to append to, created when *requirements
 *                     is NULL
 * @return NGX_CONF_OK, or an error message allocated from the
 *         configuration pool (NGX_CONF_ERROR when even that fails)
 *         when an expression does not compile
 */
char *nginx_oauth2_set_require(ngx_conf_t *cf, ngx_array_t **requirements);

/**
 * @brief Evaluate the requirements on a request.
 *
 * Evaluates the expressions in order and stops at the first one that
 * does not evaluate to exactly "1".
 *
 * @param ctx          the request context
 * @param requirements the array built by nginx_oauth2_set_require(),
 *                     NULL when no requirements were configured
 * @return NGX_OK when every requirement is satisfied (or there are
 *         none), NGX_HTTP_UNAUTHORIZED when one is not, NGX_ERROR when
 *         an expression could not be evaluated
 */
ngx_int_t nginx_oauth2_check_requirements(oauth2_nginx_request_context_t *ctx,
					  ngx_array_t *requirements);
/** @} */

#endif /* _OAUTH2_NGINX_H_ */
