#ifndef _OAUTH2_APACHE_H_
#define _OAUTH2_APACHE_H_

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

extern oauth2_cfg_server_callback_funcs_t oauth2_apache_server_callback_funcs;

/*
 * logging
 */

extern oauth2_uint_t log_level_log2apache[];
extern oauth2_uint_t log_level_apache2oauth2[];

#ifndef APLOG_USE_MODULE
#define APLOG_USE_MODULE(foo)                                                  \
	extern module AP_MODULE_DECLARE_DATA foo##_module;                     \
	AP_MAYBE_UNUSED(static int *const aplog_module_index) =                \
	    &(foo##_module.module_index)
#endif

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

/*
 * parent/child cleanup
 */

apr_status_t oauth2_apache_child_cleanup(void *data, module *m,
					 const char *package_name_version);

#define OAUTH2_APACHE_CHILD_CLEANUP(foo)                                       \
	static apr_status_t foo##_child_cleanup(void *data)                    \
	{                                                                      \
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,                       \
			     (const server_rec *)data, "%s: %s", __FUNCTION__, \
			     "enter");                                         \
		return oauth2_apache_child_cleanup(                            \
		    data, &foo##_module, OAUTH2_PACKAGE_NAME_VERSION);         \
	}

apr_status_t oauth2_apache_parent_cleanup(void *data, module *m,
					  const char *package_name_version);

#define OAUTH2_APACHE_PARENT_CLEANUP(foo)                                      \
	static apr_status_t foo##_parent_cleanup(void *data)                   \
	{                                                                      \
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,                       \
			     (const server_rec *)data, "%s: %s", __FUNCTION__, \
			     "enter");                                         \
		return oauth2_apache_parent_cleanup(                           \
		    data, &foo##_module, OAUTH2_PACKAGE_NAME_VERSION);         \
	}

/*
 * post config
 */

int oauth2_apache_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2,
			      server_rec *s, module *m,
			      const char *package_name_version,
			      apr_status_t (*parent_cleanup)(void *),
			      apr_status_t (*child_cleanup)(void *));

#define OAUTH2_APACHE_POST_CONFIG(foo) foo##_post_config

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

/*
 * directory config
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

#define OAUTH2_APACHE_CMD_ARGS(module, nargs, cmd, member, desc)               \
	AP_INIT_TAKE##nargs(cmd, apache_##module##_set_##member, NULL,         \
			    RSRC_CONF | ACCESS_CONF | OR_AUTHCFG, desc)

#define OAUTH2_APACHE_DIR_CTX(type, method) oauth2_##type##_dir_##method

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

/*
 * server config
 */

typedef struct oauth2_apache_cfg_srv_t {
	oauth2_log_sink_t *sink;
	oauth2_log_t *log;
	bool is_child;
} oauth2_apache_cfg_srv_t;

void *oauth2_apache_cfg_srv_create(apr_pool_t *pool, server_rec *s,
				   oauth2_log_function_t server_log_cb);
void *oauth2_apache_cfg_srv_merge(apr_pool_t *pool, void *b, void *a);

/*
 * handlers
 */

#define OAUTH2_APACHE_HANDLERS(foo)                                            \
	OAUTH2_APACHE_CHILD_CLEANUP(foo)                                       \
	OAUTH2_APACHE_PARENT_CLEANUP(foo)                                      \
	OAUTH2_APACHE_POST_CONFIG_IMPL(foo)

/*
 * module config
 */

#define OAUTH2_APACHE_COMMANDS(foo) foo##_commands
#define OAUTH2_APACHE_REGISTER_HOOKS(foo) foo##_register_hooks

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

#define OAUTH2_APACHE_MODULE_DECLARE(foo, type)                                \
                                                                               \
	OAUTH2_APACHE_DIR_CTX_FUNCS(type)                                      \
                                                                               \
	OAUTH2_APACHE_MODULE_DECLARE_EX(foo,                                   \
					OAUTH2_APACHE_DIR_CTX(type, create),   \
					OAUTH2_APACHE_DIR_CTX(type, merge))

/*
 * request context
 */

#define OAUTH2_APACHE_REQUEST_CTX(r, foo)                                      \
	oauth2_apache_request_context(                                         \
	    r, foo##_log_request,                                              \
	    "oauth2_" OAUTH2_TOSTRING(foo) "_module_user_data_key");

typedef struct oauth2_apache_request_ctx_t {
	oauth2_log_t *log;
	oauth2_http_request_t *request;
	request_rec *r;
} oauth2_apache_request_ctx_t;

oauth2_apache_request_ctx_t *
oauth2_apache_request_context(request_rec *r,
			      oauth2_log_function_t request_log_cb,
			      const char *user_data_key);

/*
 * misc
 */

bool oauth2_apache_http_request_set(oauth2_log_t *log,
				    oauth2_http_request_t *request,
				    request_rec *r);
int oauth2_apache_return_www_authenticate(oauth2_cfg_source_token_t *cfg,
					  oauth2_apache_request_ctx_t *ctx,
					  int status_code, const char *error,
					  const char *error_description);
bool oauth2_apache_request_header_set(oauth2_log_t *log, void *rec,
				      const char *name, const char *value);
void oauth2_apache_hdr_out_set(oauth2_log_t *log, const request_rec *r,
			       const char *name, const char *value);
void oauth2_apache_scrub_headers(oauth2_apache_request_ctx_t *ctx,
				 oauth2_cfg_target_pass_t *target_pass);
bool oauth2_apache_set_request_user(oauth2_cfg_target_pass_t *target_pass,
				    oauth2_apache_request_ctx_t *ctx,
				    json_t *json_token);
void oauth2_apache_target_pass(oauth2_apache_request_ctx_t *ctx,
			       oauth2_cfg_target_pass_t *target_pass,
			       const char *target_token, json_t *json_token);

bool oauth2_apache_http_response_set(oauth2_log_t *log,
				     oauth2_http_response_t *response,
				     request_rec *r);

void oauth2_apache_request_state_set_json(oauth2_apache_request_ctx_t *ctx,
					  const char *key, json_t *claims);
void oauth2_apache_request_state_get_json(oauth2_apache_request_ctx_t *ctx,
					  const char *key, json_t **claims);

typedef bool (*oauth2_apache_authz_match_claim_fn_type)(
    oauth2_apache_request_ctx_t *, const char *const, const json_t *const);

bool oauth2_apache_authz_match_claim(oauth2_apache_request_ctx_t *ctx,
				     const char *const attr_spec,
				     const json_t *const claims);
authz_status
oauth2_apache_authorize(oauth2_apache_request_ctx_t *ctx,
			const json_t *const claims, const char *require_args,
			oauth2_apache_authz_match_claim_fn_type match_claim_fn);

#endif /* _OAUTH2_APACHE_H_ */
