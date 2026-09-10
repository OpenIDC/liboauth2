#ifndef _OAUTH2_APACHE_H_
#define _OAUTH2_APACHE_H_

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
 * @file apache.h
 * @brief Apache httpd binding.
 *
 * The liboauth2_apache library adapts the server-agnostic core to
 * Apache httpd 2.x, for modules such as mod_oauth2 and mod_sts: it
 * maps the native request_rec and server_rec onto the
 * oauth2_http_request_t / oauth2_http_response_t abstraction (http.h)
 * and onto log sinks (log.h), passes verified claims on to the target
 * application and evaluates Require directives against them, and
 * provides the macros that generate a module's boilerplate: the log
 * callbacks, the cleanup and post_config hooks, the directive
 * handlers, the per-server config and the module record itself.
 *
 * Towards these macros a module is identified by a short name - "foo"
 * below, e.g. oauth2 for mod_oauth2 - from which the generated and the
 * expected symbols are derived: the module record is foo_module, the
 * command table foo_commands and the hook registration function
 * foo_register_hooks. The module must also define
 * OAUTH2_PACKAGE_NAME_VERSION to its "\<name\>-\<version\>" string (e.g.
 * "mod_oauth2-4.2.0"), which is used in log messages and as the key
 * that marks the post_config pass.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oauth2/http.h>
#include <oauth2/log.h>
#include <oauth2/util.h>
#include <oauth2/version.h>

// avoid errors about ap_auto_config overriding these, so undefine first
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <httpd.h>

#include <http_config.h>
#include <http_log.h>

#include <mod_auth.h>

/**
 * @brief Storage class of the data symbols liboauth2_apache exports.
 *
 * See OAUTH2_EXTERN in log.h: the same for the data that liboauth2_apache
 * exports, which is a library of its own (OAUTH2_APACHE_EXPORTS when building
 * it, OAUTH2_APACHE_STATIC when its objects are linked in directly).
 */
#if defined(_WIN32) && !defined(OAUTH2_APACHE_STATIC)
#ifdef OAUTH2_APACHE_EXPORTS
#define OAUTH2_APACHE_EXTERN __declspec(dllexport) extern
#else
#define OAUTH2_APACHE_EXTERN __declspec(dllimport) extern
#endif
#else
#define OAUTH2_APACHE_EXTERN extern
#endif

/**
 * @brief The server callbacks the core needs from this binding.
 *
 * Reads and sets environment variables in the request's
 * subprocess_env table and reads a form-encoded POST body (at most 1
 * MB), all with the request_rec as callback context. Pass it,
 * together with the request_rec, to the functions that take an
 * oauth2_cfg_server_callback_funcs_t, such as
 * oauth2_get_source_token() (proto.h).
 */
OAUTH2_APACHE_EXTERN oauth2_cfg_server_callback_funcs_t
    oauth2_apache_server_callback_funcs;

/**
 * @name Logging
 * A module logs through oauth2_log_sink_t objects whose callbacks
 * forward to ap_log_error() (server scope) or ap_log_rerror() (request
 * scope); the level maps translate between the httpd (APLOG_*) and
 * the library (OAUTH2_LOG_*) log levels in both directions.
 * @{
 */

/** @brief Library log level (OAUTH2_LOG_*) to httpd level (APLOG_*). */
OAUTH2_APACHE_EXTERN oauth2_uint_t log_level_log2apache[];
/** @brief httpd log level (APLOG_*) to library log level (OAUTH2_LOG_*). */
OAUTH2_APACHE_EXTERN oauth2_uint_t log_level_apache2oauth2[];

/**
 * @brief Backport of httpd's APLOG_USE_MODULE for versions that lack
 *        it: makes the module's log messages carry its module index.
 */
#ifndef APLOG_USE_MODULE
#define APLOG_USE_MODULE(foo)                                                  \
	extern module AP_MODULE_DECLARE_DATA foo##_module;                     \
	AP_MAYBE_UNUSED(static int *const aplog_module_index) =                \
	    &(foo##_module.module_index)
#endif

/**
 * @brief Generate a module's log sink callbacks.
 *
 * Expands to APLOG_USE_MODULE(foo) plus two static functions,
 * foo_log_server() and foo_log_request(): the oauth2_log_function_t
 * callbacks of the server and request log sinks created by
 * oauth2_apache_cfg_srv_create() and oauth2_apache_request_context(),
 * logging "\<function\>: \<message\>" through ap_log_error() and
 * ap_log_rerror() with the sink's context as the server_rec or
 * request_rec. Use it once, near the top of the module source, since
 * the other macros refer to the functions it generates.
 *
 * @param foo the module's short name
 */
#define OAUTH2_APACHE_LOG(foo)                                                 \
                                                                               \
	APLOG_USE_MODULE(foo);                                                 \
                                                                               \
	static void foo##_log_server(                                          \
	    oauth2_log_sink_t *sink, const char *filename, unsigned long line, \
	    const char *function, oauth2_log_level_t level, const char *msg)   \
	{                                                                      \
		ap_log_error(                                                  \
		    filename, line,                                            \
		    aplog_module_index ? *aplog_module_index                   \
				       : APLOG_NO_MODULE,                      \
		    log_level_log2apache[level], 0,                            \
		    (const server_rec *)oauth2_log_sink_ctx_get(sink),         \
		    "%s: %s", function, msg);                                  \
	}                                                                      \
                                                                               \
	static void foo##_log_request(                                         \
	    oauth2_log_sink_t *sink, const char *filename, unsigned long line, \
	    const char *function, oauth2_log_level_t level, const char *msg)   \
	{                                                                      \
		ap_log_rerror(                                                 \
		    filename, line,                                            \
		    aplog_module_index ? *aplog_module_index                   \
				       : APLOG_NO_MODULE,                      \
		    log_level_log2apache[level], 0,                            \
		    (const request_rec *)oauth2_log_sink_ctx_get(sink),        \
		    "%s: %s", function, msg);                                  \
	}

/** @} */

/**
 * @name Parent/child cleanup
 * The pool cleanups that oauth2_apache_post_config() registers on the
 * configuration pool; both end in oauth2_shutdown() (util.h), which
 * releases the global cache, session, libcurl and OpenSSL state.
 * @{
 */

/**
 * @brief Child cleanup: calls oauth2_shutdown().
 *
 * @param data                 the server_rec the cleanup was
 *                             registered with
 * @param m                    the module record
 * @param package_name_version the module's "\<name\>-\<version\>" string
 * @return APR_SUCCESS
 */
apr_status_t oauth2_apache_child_cleanup(void *data, module *m,
					 const char *package_name_version);

/**
 * @brief Generate foo_child_cleanup(), the apr pool cleanup function
 *        that logs "enter" at debug level and calls
 *        oauth2_apache_child_cleanup() for foo_module and
 *        OAUTH2_PACKAGE_NAME_VERSION.
 */
#define OAUTH2_APACHE_CHILD_CLEANUP(foo)                                       \
	static apr_status_t foo##_child_cleanup(void *data)                    \
	{                                                                      \
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,                       \
			     (const server_rec *)data, "%s: %s", __FUNCTION__, \
			     "enter");                                         \
		return oauth2_apache_child_cleanup(                            \
		    data, &foo##_module, OAUTH2_PACKAGE_NAME_VERSION);         \
	}

/**
 * @brief Parent cleanup: logs the module shutdown through the server
 *        config's log and calls oauth2_apache_child_cleanup().
 *
 * @param data                 the server_rec the cleanup was
 *                             registered with
 * @param m                    the module record, used to look up the
 *                             module's oauth2_apache_cfg_srv_t
 * @param package_name_version the module's "\<name\>-\<version\>" string
 * @return APR_SUCCESS
 */
apr_status_t oauth2_apache_parent_cleanup(void *data, module *m,
					  const char *package_name_version);

/**
 * @brief Generate foo_parent_cleanup(), the apr pool cleanup function
 *        that logs "enter" at debug level and calls
 *        oauth2_apache_parent_cleanup() for foo_module and
 *        OAUTH2_PACKAGE_NAME_VERSION.
 */
#define OAUTH2_APACHE_PARENT_CLEANUP(foo)                                      \
	static apr_status_t foo##_parent_cleanup(void *data)                   \
	{                                                                      \
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,                       \
			     (const server_rec *)data, "%s: %s", __FUNCTION__, \
			     "enter");                                         \
		return oauth2_apache_parent_cleanup(                           \
		    data, &foo##_module, OAUTH2_PACKAGE_NAME_VERSION);         \
	}

/** @} */

/**
 * @name Post config
 * @{
 */

/**
 * @brief The post_config hook implementation shared by all modules.
 *
 * Does nothing on httpd's first, configuration-checking pass through
 * post_config, which it detects through a marker it leaves in the
 * process pool's userdata under @p package_name_version. On the
 * second pass it initializes the library with oauth2_init() (OpenSSL
 * and libcurl), sets the level of every virtual host's server log
 * sink to the LogLevel that is only known by now, registers
 * @p parent_cleanup and @p child_cleanup as the plain and the child
 * cleanup of @p pool (see apr_pool_cleanup_register()), retrieves
 * mod_ssl's ssl_var_lookup optional function - used to obtain the
 * client certificate for mTLS-bound tokens - and logs an "init"
 * message with the module and library versions.
 *
 * @param pool                 the configuration pool
 * @param p1                   the log pool
 * @param p2                   the temporary pool
 * @param s                    the main server record
 * @param m                    the module record
 * @param package_name_version the module's "\<name\>-\<version\>" string
 * @param parent_cleanup       the parent cleanup function
 * @param child_cleanup        the child cleanup function
 * @return OK
 */
int oauth2_apache_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2,
			      server_rec *s, module *m,
			      const char *package_name_version,
			      apr_status_t (*parent_cleanup)(void *),
			      apr_status_t (*child_cleanup)(void *));

/** @brief The name of the generated post_config hook: foo_post_config. */
#define OAUTH2_APACHE_POST_CONFIG(foo) foo##_post_config

/**
 * @brief Generate foo_post_config(), a static function with httpd's
 *        post_config hook signature that logs "enter" at debug level
 *        and calls oauth2_apache_post_config() for foo_module,
 *        OAUTH2_PACKAGE_NAME_VERSION and the foo_parent_cleanup() and
 *        foo_child_cleanup() functions.
 *
 * The module registers it from foo_register_hooks() with
 * ap_hook_post_config(OAUTH2_APACHE_POST_CONFIG(foo), ...).
 */
#define OAUTH2_APACHE_POST_CONFIG_IMPL(foo)                                    \
	static apr_status_t OAUTH2_APACHE_POST_CONFIG(foo)(                    \
	    apr_pool_t * pool, apr_pool_t * p1, apr_pool_t * p2,               \
	    server_rec * s)                                                    \
	{                                                                      \
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,                       \
			     (const server_rec *)s, "%s: %s", __FUNCTION__,    \
			     "enter");                                         \
		return oauth2_apache_post_config(                              \
		    pool, p1, p2, s, &foo##_module,                            \
		    OAUTH2_PACKAGE_NAME_VERSION, foo##_parent_cleanup,         \
		    foo##_child_cleanup);                                      \
	}

/** @} */

/**
 * @name Directory config
 * Directive handlers and per-directory configuration.
 * OAUTH2_APACHE_CMD_ARGS1(), OAUTH2_APACHE_CMD_ARGS2(),
 * OAUTH2_APACHE_CMD_ARGS3() and OAUTH2_APACHE_CMD_ARGSV4() each
 * generate a static directive handler apache_\<module\>_set_\<primitive\>()
 * with the signature of an AP_INIT_TAKE1, TAKE2, TAKE3 or TAKE_ARGV
 * command: it fetches the module's oauth2_apache_cfg_srv_t for its
 * log and hands the directive's arguments to a liboauth2 configuration
 * setter as func(log, member, v1, ...), which returns NULL on success
 * or an error string that httpd reports as a configuration error.
 * OAUTH2_APACHE_CMD_ARGS() then builds the command_rec entry that
 * refers to such a handler.
 * @{
 */

/**
 * @brief Generate the handler for a directive taking one argument.
 *
 * @param module    the module's short name (the module record is
 *                  module_module)
 * @param type      the module's per-directory config struct type
 * @param primitive the name of the generated handler
 *                  apache_\<module\>_set_\<primitive\>(); pass the same
 *                  name as the "member" argument of
 *                  OAUTH2_APACHE_CMD_ARGS()
 * @param func      the setter to call, returning NULL on success or an
 *                  error string, as the oauth2_cfg_*_set* functions in
 *                  cfg.h do
 * @param member    the setter's target: an expression evaluated inside
 *                  the handler with the per-directory config in scope
 *                  as "cfg" (e.g. cfg->source_token or &cfg->verify),
 *                  or NULL for global setters such as
 *                  oauth2_cfg_set_cache()
 */
#define OAUTH2_APACHE_CMD_ARGS1(module, type, primitive, func, member)         \
	static const char *apache_##module##_set_##primitive(                  \
	    cmd_parms *cmd, void *m, const char *v1)                           \
	{                                                                      \
		oauth2_apache_cfg_srv_t *srv_cfg = ap_get_module_config(       \
		    cmd->server->module_config, &module##_module);             \
		type *cfg = (type *)m;                                         \
		(void)cfg;                                                     \
		return func(srv_cfg->log, member, v1);                         \
	}

/**
 * @brief Generate the handler for a directive taking two arguments;
 *        the parameters are as for OAUTH2_APACHE_CMD_ARGS1().
 */
#define OAUTH2_APACHE_CMD_ARGS2(module, type, primitive, func, member)         \
	static const char *apache_##module##_set_##primitive(                  \
	    cmd_parms *cmd, void *m, const char *v1, const char *v2)           \
	{                                                                      \
		oauth2_apache_cfg_srv_t *srv_cfg = ap_get_module_config(       \
		    cmd->server->module_config, &module##_module);             \
		type *cfg = (type *)m;                                         \
		(void)cfg;                                                     \
		return func(srv_cfg->log, member, v1, v2);                     \
	}

/**
 * @brief Generate the handler for a directive taking three arguments;
 *        the parameters are as for OAUTH2_APACHE_CMD_ARGS1().
 */
#define OAUTH2_APACHE_CMD_ARGS3(module, type, primitive, func, member)         \
	static const char *apache_##module##_set_##primitive(                  \
	    cmd_parms *cmd, void *m, const char *v1, const char *v2,           \
	    const char *v3)                                                    \
	{                                                                      \
		oauth2_apache_cfg_srv_t *srv_cfg = ap_get_module_config(       \
		    cmd->server->module_config, &module##_module);             \
		type *cfg = (type *)m;                                         \
		(void)cfg;                                                     \
		return func(srv_cfg->log, member, v1, v2, v3);                 \
	}

/**
 * @brief Generate the handler for a directive taking a variable number
 *        of arguments (AP_INIT_TAKE_ARGV), up to four; the arguments
 *        not given are passed to the setter as NULL. The parameters
 *        are as for OAUTH2_APACHE_CMD_ARGS1().
 */
#define OAUTH2_APACHE_CMD_ARGSV4(module, type, primitive, func, member)        \
	static const char *apache_##module##_set_##primitive(                  \
	    cmd_parms *cmd, void *m, int argc, char *const argv[])             \
	{                                                                      \
		oauth2_apache_cfg_srv_t *srv_cfg = ap_get_module_config(       \
		    cmd->server->module_config, &module##_module);             \
		type *cfg = (type *)m;                                         \
		(void)cfg;                                                     \
		return func(srv_cfg->log, member, argc > 0 ? argv[0] : NULL,   \
			    argc > 1 ? argv[1] : NULL,                         \
			    argc > 2 ? argv[2] : NULL,                         \
			    argc > 3 ? argv[3] : NULL);                        \
	}

/**
 * @brief Generate a command_rec entry for a directive.
 *
 * Expands to AP_INIT_TAKE\<nargs\>(cmd, apache_\<module\>_set_\<member\>,
 * ...), allowing the directive in the server config, in directory and
 * location sections and in .htaccess files with AuthConfig override
 * (RSRC_CONF | ACCESS_CONF | OR_AUTHCFG).
 *
 * @param module the module's short name
 * @param nargs  the suffix of the AP_INIT_TAKE macro to use: 1, 2, 3,
 *               12, 23, _ARGV, ...; must accept the number of
 *               arguments the handler was generated for
 * @param cmd    the directive name, e.g. "OAuth2TokenVerify"
 * @param member the "primitive" name the handler was generated with
 * @param desc   the directive's description, shown by httpd -L
 */
#define OAUTH2_APACHE_CMD_ARGS(module, nargs, cmd, member, desc)               \
	AP_INIT_TAKE##nargs(cmd, apache_##module##_set_##member, NULL,         \
			    RSRC_CONF | ACCESS_CONF | OR_AUTHCFG, desc)

/**
 * @brief The name of a per-directory config function generated by
 *        OAUTH2_APACHE_DIR_CTX_FUNCS(): oauth2_\<type\>_dir_\<method\>.
 */
#define OAUTH2_APACHE_DIR_CTX(type, method) oauth2_##type##_dir_##method

/**
 * @brief Generate the per-directory config functions for a config type.
 *
 * For a per-directory config type following the library's object
 * conventions - oauth2_\<type\>_t with oauth2_\<type\>_create(log, path),
 * oauth2_\<type\>_merge(log, cfg, base, add) and oauth2_\<type\>_free(log,
 * cfg) - generates oauth2_\<type\>_dir_create() (allocates a config for
 * the directory or location path and registers its release as a pool
 * cleanup) and the static oauth2_\<type\>_dir_merge() (creates a new
 * config and merges the base and the more specific config into it),
 * the create_dir_config and merge_dir_config functions of the module
 * record, plus oauth2_\<type\>_dir_cleanup(), the pool cleanup.
 *
 * @param type the config type's name, e.g. sts_cfg for oauth2_sts_cfg_t
 */
#define OAUTH2_APACHE_DIR_CTX_FUNCS(type)                                      \
	apr_status_t OAUTH2_APACHE_DIR_CTX(type, cleanup)(void *data)          \
	{                                                                      \
		oauth2_##type##_t *cfg = (oauth2_##type##_t *)data;            \
		oauth2_##type##_free(NULL, cfg);                               \
		return APR_SUCCESS;                                            \
	}                                                                      \
                                                                               \
	void *OAUTH2_APACHE_DIR_CTX(type, create)(apr_pool_t * pool,           \
						  char *path)                  \
	{                                                                      \
		oauth2_##type##_t *cfg = oauth2_##type##_create(NULL, path);   \
		apr_pool_cleanup_register(                                     \
		    pool, cfg, OAUTH2_APACHE_DIR_CTX(type, cleanup),           \
		    OAUTH2_APACHE_DIR_CTX(type, cleanup));                     \
		return cfg;                                                    \
	}                                                                      \
                                                                               \
	static void *OAUTH2_APACHE_DIR_CTX(type, merge)(apr_pool_t * pool,     \
							void *b, void *a)      \
	{                                                                      \
		oauth2_##type##_t *cfg =                                       \
		    OAUTH2_APACHE_DIR_CTX(type, create)(pool, NULL);           \
		oauth2_##type##_t *base = b;                                   \
		oauth2_##type##_t *add = a;                                    \
		oauth2_##type##_merge(NULL, cfg, base, add);                   \
		return cfg;                                                    \
	}

/** @} */

/**
 * @name Server config
 * The per-server (virtual host) config this binding keeps for a
 * module: the server-scoped log sink and log handle, used where there
 * is no request, e.g. in the directive handlers and at shutdown.
 * @{
 */

typedef struct oauth2_apache_cfg_srv_t {
	/** @brief The server log sink: foo_log_server() with the server_rec
	 *         as context. */
	oauth2_log_sink_t *sink;
	/** @brief The server-scoped log handle. */
	oauth2_log_t *log;
	/** @brief Unused. */
	bool is_child;
} oauth2_apache_cfg_srv_t;

/**
 * @brief Create a server config, the module record's
 *        create_server_config function.
 *
 * Creates the log sink with @p server_log_cb and @p s as its context
 * and the log handle, at the server's LogLevel when already known and
 * at trace1 otherwise (oauth2_apache_post_config() sets the definitive
 * level later), and registers their release as a cleanup of @p pool.
 *
 * @param pool          the pool to register the cleanup on
 * @param s             the server record
 * @param server_log_cb the foo_log_server() function generated by
 *                      OAUTH2_APACHE_LOG()
 * @return the new oauth2_apache_cfg_srv_t
 */
void *oauth2_apache_cfg_srv_create(apr_pool_t *pool, server_rec *s,
				   oauth2_log_function_t server_log_cb);
/**
 * @brief Merge server configs, the module record's
 *        merge_server_config function: creates a fresh config for the
 *        virtual host's server_rec.
 *
 * @param pool the pool to register the cleanup on
 * @param b    the base (main server) config
 * @param a    the virtual host's config
 * @return the new oauth2_apache_cfg_srv_t
 */
void *oauth2_apache_cfg_srv_merge(apr_pool_t *pool, void *b, void *a);

/** @} */

/**
 * @name Handlers
 * @{
 */

/**
 * @brief Generate the three hook functions a module gets from this
 *        binding: OAUTH2_APACHE_CHILD_CLEANUP(),
 *        OAUTH2_APACHE_PARENT_CLEANUP() and
 *        OAUTH2_APACHE_POST_CONFIG_IMPL() for foo.
 */
#define OAUTH2_APACHE_HANDLERS(foo)                                            \
	OAUTH2_APACHE_CHILD_CLEANUP(foo)                                       \
	OAUTH2_APACHE_PARENT_CLEANUP(foo)                                      \
	OAUTH2_APACHE_POST_CONFIG_IMPL(foo)

/** @} */

/**
 * @name Module config
 * @{
 */

/** @brief The name of the module's command_rec table: foo_commands. */
#define OAUTH2_APACHE_COMMANDS(foo) foo##_commands
/**
 * @brief The name of the module's hook registration function:
 *        foo_register_hooks.
 */
#define OAUTH2_APACHE_REGISTER_HOOKS(foo) foo##_register_hooks

/**
 * @brief Generate the module record.
 *
 * Defines oauth2_apache_foo_cfg_srv_create(), which binds
 * oauth2_apache_cfg_srv_create() to foo_log_server(), and the exported
 * module record foo_module with the given per-directory config
 * functions, the binding's server config create and merge functions,
 * the command table foo_commands and the hook registration function
 * foo_register_hooks. The module must have defined the command table
 * and the hook function, as well as OAUTH2_APACHE_LOG(foo) and
 * OAUTH2_APACHE_HANDLERS(foo), before using this macro.
 *
 * @param foo        the module's short name
 * @param dir_create the create_dir_config function
 * @param dir_merge  the merge_dir_config function
 */
#define OAUTH2_APACHE_MODULE_DECLARE_EX(foo, dir_create, dir_merge)            \
                                                                               \
	void *oauth2_apache_##foo##_cfg_srv_create(apr_pool_t *pool,           \
						   server_rec *s)              \
	{                                                                      \
		return oauth2_apache_cfg_srv_create(pool, s,                   \
						    foo##_log_server);         \
	}                                                                      \
                                                                               \
	module AP_MODULE_DECLARE_DATA foo##_module = {                         \
	    STANDARD20_MODULE_STUFF,                                           \
	    dir_create,                                                        \
	    dir_merge,                                                         \
	    oauth2_apache_##foo##_cfg_srv_create,                              \
	    oauth2_apache_cfg_srv_merge,                                       \
	    OAUTH2_APACHE_COMMANDS(foo),                                       \
	    OAUTH2_APACHE_REGISTER_HOOKS(foo)};

/**
 * @brief Generate the per-directory config functions with
 *        OAUTH2_APACHE_DIR_CTX_FUNCS() for @p type and the module
 *        record with OAUTH2_APACHE_MODULE_DECLARE_EX() using them.
 */
#define OAUTH2_APACHE_MODULE_DECLARE(foo, type)                                \
                                                                               \
	OAUTH2_APACHE_DIR_CTX_FUNCS(type)                                      \
                                                                               \
	OAUTH2_APACHE_MODULE_DECLARE_EX(foo,                                   \
					OAUTH2_APACHE_DIR_CTX(type, create),   \
					OAUTH2_APACHE_DIR_CTX(type, merge))

/** @} */

/**
 * @name Request context
 * The per-request state this binding keeps for a module: a
 * request-scoped log handle, whose sink is foo_log_request() with the
 * request_rec as context, and the abstract oauth2_http_request_t
 * populated from the request_rec, on which the core operates.
 * @{
 */

/**
 * @brief Get the request context for @p r, calling
 *        oauth2_apache_request_context() with foo_log_request() and a
 *        userdata key derived from the module name.
 */
#define OAUTH2_APACHE_REQUEST_CTX(r, foo)                                      \
	oauth2_apache_request_context(                                         \
	    r, foo##_log_request,                                              \
	    "oauth2_" OAUTH2_TOSTRING(foo) "_module_user_data_key");

typedef struct oauth2_apache_request_ctx_t {
	/** @brief The request-scoped log handle. */
	oauth2_log_t *log;
	/** @brief The abstract request populated from r. */
	oauth2_http_request_t *request;
	/** @brief The (main) request record. */
	request_rec *r;
} oauth2_apache_request_ctx_t;

/**
 * @brief Get, creating it on first use, the request context.
 *
 * The context is created once per main request - for a subrequest the
 * main request's context is returned - and cached in the request
 * pool's userdata under @p user_data_key, with a cleanup that releases
 * it when the request is done. On creation the log handle is set up
 * at the request's LogLevel and the abstract request is populated
 * with the scheme, the server name as used in self-referential URLs,
 * the local port, the URI path, the method, the query string and all
 * incoming headers. The client's TLS certificate, looked up through
 * mod_ssl's ssl_var_lookup as SSL_CLIENT_CERT, is stored in the
 * request's context under OAUTH2_TLS_CERT_VAR_NAME (http.h) for
 * verifying mTLS-bound tokens, since mod_ssl's own environment
 * variables only become available in the fixups phase.
 *
 * @param r              the request record
 * @param request_log_cb the foo_log_request() function generated by
 *                       OAUTH2_APACHE_LOG()
 * @param user_data_key  the pool userdata key to cache the context
 *                       under, unique per module
 * @return the request context, owned by the request pool
 */
oauth2_apache_request_ctx_t *
oauth2_apache_request_context(request_rec *r,
			      oauth2_log_function_t request_log_cb,
			      const char *user_data_key);

/** @} */

/**
 * @name Request and response handling
 * @{
 */

/**
 * @brief Apply an abstract request back onto the request_rec.
 *
 * Sets every header of @p request as an incoming header of @p r,
 * overwriting headers of the same name, and replaces the request's
 * query string with the one in @p request. Used after
 * oauth2_get_source_token() (proto.h) stripped the token from the
 * request, so that the target application does not see it.
 *
 * @param log     the log handle to use
 * @param request the abstract request
 * @param r       the request record to update
 * @return true on success, false when @p request is NULL
 */
bool oauth2_apache_http_request_set(oauth2_log_t *log,
				    oauth2_http_request_t *request,
				    request_rec *r);
/**
 * @brief Add a WWW-Authenticate challenge to the response and return
 *        the status code to end the handler with.
 *
 * The challenge's scheme is "Basic" when the source token
 * configuration accepts the token in the basic authentication header
 * only and "Bearer" otherwise; the AuthName of the location, when
 * set, is added as its realm and @p error and @p error_description,
 * when not NULL, as the RFC 6750 section 3 attributes. The header is
 * added to the error headers, so it is sent with the error response.
 *
 * @param cfg               the source token configuration
 * @param ctx               the request context
 * @param status_code       the status code to return, typically
 *                          HTTP_UNAUTHORIZED
 * @param error             the "error" attribute, e.g.
 *                          OAUTH2_ERROR_INVALID_TOKEN (oauth2.h), or
 *                          NULL
 * @param error_description the "error_description" attribute, or NULL
 * @return @p status_code
 */
int oauth2_apache_return_www_authenticate(oauth2_cfg_source_token_t *cfg,
					  oauth2_apache_request_ctx_t *ctx,
					  int status_code, const char *error,
					  const char *error_description);
/**
 * @brief Set an incoming request header, overwriting an existing one.
 *
 * @param log   the log handle to use
 * @param rec   the request_rec, typed void so this can serve as the
 *              callback of oauth2_http_request_headers_loop()
 * @param name  the header name
 * @param value the header value
 * @return true
 */
bool oauth2_apache_request_header_set(oauth2_log_t *log, void *rec,
				      const char *name, const char *value);
/**
 * @brief Add an outgoing response header.
 *
 * The header goes into the request's err_headers_out table, so that it
 * is sent with error responses as well and survives internal
 * redirects.
 *
 * @param log   the log handle to use
 * @param r     the request record
 * @param name  the header name
 * @param value the header value
 */
void oauth2_apache_hdr_out_add(oauth2_log_t *log, const request_rec *r,
			       const char *name, const char *value);
/**
 * @brief Remove incoming headers a client could use to spoof claims.
 *
 * When the target pass configuration passes claims as headers, drops
 * every incoming request header whose name starts with the configured
 * header prefix, and the configured authentication header, from the
 * request, logging a warning for each; nothing is done when claims
 * are passed as environment variables only. Call before passing
 * claims with oauth2_apache_target_pass().
 *
 * @param ctx         the request context
 * @param target_pass the target pass configuration
 */
void oauth2_apache_scrub_headers(oauth2_apache_request_ctx_t *ctx,
				 oauth2_cfg_target_pass_t *target_pass);
/**
 * @brief Set the request's authenticated user from the token claims.
 *
 * Sets r->user to the value of the string claim named by the target
 * pass configuration's "remote_user_claim" option (default "sub").
 *
 * @param target_pass the target pass configuration
 * @param ctx         the request context
 * @param json_token  the claims of the verified token
 * @return true when the user was set, false - having logged an error -
 *         when either argument is NULL, no remote user claim is
 *         configured, or the claim is absent or not a string
 */
bool oauth2_apache_set_request_user(oauth2_cfg_target_pass_t *target_pass,
				    oauth2_apache_request_ctx_t *ctx,
				    json_t *json_token);
/**
 * @brief Pass the token and its claims on to the target application.
 *
 * Per the target pass configuration, passes:
 * - the request's user (r->user) in the configured authentication
 *   header, when both are set;
 * - each claim of @p json_token as a header and/or an environment
 *   variable named "\<prefix\>\<claim name\>", the name with characters
 *   that are not allowed in a header name replaced by "-", and the
 *   value - non-string claims JSON-encoded - encoded per the
 *   configured encoding ("none", "latin1" or "base64url");
 * - @p target_token, when not NULL, as "\<prefix\>access_token";
 * - when a JSON payload claim name is configured, all claims as one
 *   compact JSON object under that name.
 *
 * @param ctx          the request context
 * @param target_pass  the target pass configuration
 * @param target_token the token to pass on, or NULL
 * @param json_token   the claims to pass on
 */
void oauth2_apache_target_pass(oauth2_apache_request_ctx_t *ctx,
			       oauth2_cfg_target_pass_t *target_pass,
			       const char *target_token, json_t *json_token);

/**
 * @brief Apply an abstract response onto the request_rec.
 *
 * Adds every header of @p response, including any Set-Cookie headers,
 * to the request's error headers with oauth2_apache_hdr_out_add() and
 * sets r->status to the response's status code. No body is written:
 * the handler returns the status code to let httpd generate the
 * response, as for the redirects and error responses of the OpenID
 * Connect RP flow (openidc.h).
 *
 * @param log      the log handle to use
 * @param response the abstract response
 * @param r        the request record to update
 * @return true on success, false when either argument is NULL
 */
bool oauth2_apache_http_response_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     request_rec *r);

/**
 * @brief Store a JSON object in the request state.
 *
 * The request state is a table in the main request's pool userdata,
 * shared by all modules using this binding and by the subrequests of
 * the main request; the object is stored serialized.
 *
 * @param ctx    the request context
 * @param key    the key to store the object under
 * @param claims the JSON object to store
 */
void oauth2_apache_request_state_set_json(oauth2_apache_request_ctx_t *ctx,
					  const char *key, json_t *claims);
/**
 * @brief Retrieve a JSON object from the request state.
 *
 * @param ctx    the request context
 * @param key    the key the object was stored under
 * @param claims when an object is stored under @p key, set to a newly
 *               decoded copy of it, to be released with json_decref();
 *               left untouched otherwise
 */
void oauth2_apache_request_state_get_json(oauth2_apache_request_ctx_t *ctx,
					  const char *key, json_t **claims);

/** @} */

/**
 * @name Authorization
 * Evaluating Require directives against the claims of the verified
 * token, for use from an authz provider registered with
 * ap_register_auth_provider().
 * @{
 */

/**
 * @brief A function matching one Require specification against the
 *        claims: the request context, the specification and the
 *        claims; oauth2_apache_authz_match_claim() is the default.
 */
typedef bool (*oauth2_apache_authz_match_claim_fn_type)(
    oauth2_apache_request_ctx_t *, const char *const, const json_t *const);

/**
 * @brief Match a claim specification against a claims object.
 *
 * The specification is a claim name followed by an operator and an
 * operand:
 * - "\<name\>:\<value\>": the claim equals the value; a string claim is
 *   compared case-sensitively, an integer claim against the value
 *   parsed as an integer, a boolean claim against "true" or "false",
 *   and an array claim matches when any of its string, integer or
 *   boolean elements does;
 * - "\<name\>~\<regex\>": the string claim, or any string element of the
 *   array claim, matches the PCRE regular expression;
 * - "\<name\>.\<spec\>": for an object claim, \<spec\> is matched
 *   recursively against its members; for an array claim, \<spec\> is a
 *   value matched against its elements as for ":".
 *
 * @param ctx       the request context
 * @param attr_spec the specification, one word of the Require
 *                  directive's arguments
 * @param claims    the claims to match against
 * @return true when a claim matches the specification, false otherwise
 *         or when @p claims is NULL
 */
bool oauth2_apache_authz_match_claim(oauth2_apache_request_ctx_t *ctx,
				     const char *const attr_spec,
				     const json_t *const claims);
/**
 * @brief Evaluate a Require directive's arguments against the claims.
 *
 * Splits @p require_args into its (possibly quoted) words and returns
 * as soon as one of them matches per @p match_claim_fn, so the words
 * are alternatives; the only way to require several claims is to use
 * several Require directives.
 *
 * @param ctx            the request context
 * @param claims         the claims of the verified token
 * @param require_args   the arguments of the Require directive, as
 *                       passed to the authz provider's
 *                       check_authorization function
 * @param match_claim_fn the function matching one word against the
 *                       claims, typically
 *                       oauth2_apache_authz_match_claim()
 * @return AUTHZ_DENIED_NO_USER when the request has no authenticated
 *         user, AUTHZ_GRANTED when a word matched, AUTHZ_DENIED
 *         otherwise - also when @p claims is NULL or, with a warning,
 *         when no words were given
 */
authz_status
oauth2_apache_authorize(oauth2_apache_request_ctx_t *ctx,
			const json_t *const claims, const char *require_args,
			oauth2_apache_authz_match_claim_fn_type match_claim_fn);
/** @} */

#endif /* _OAUTH2_APACHE_H_ */
