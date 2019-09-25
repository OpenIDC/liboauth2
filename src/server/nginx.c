/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
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

#include "oauth2/nginx.h"

#include <oauth2/http.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>

#include <ngx_log.h>

// yep, this is tightly aligned with the (sequence of...) the log levels in
// lmo/log.h, but is faaast

// clang-format off
/*
static int log_level_nginx2oauth[] = {
    OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_ERROR,
	OAUTH2_LOG_WARN,
	OAUTH2_LOG_NOTICE,
	OAUTH2_LOG_INFO,
	OAUTH2_LOG_DEBUG
};
*/

// TODO: TRACE2 to STDERR??
static int log_level_log2nginx[] = {
    NGX_LOG_ERR,
	NGX_LOG_WARN,
	NGX_LOG_NOTICE,
	NGX_LOG_INFO,
    NGX_LOG_DEBUG,
	NGX_LOG_DEBUG,
	NGX_LOG_STDERR
};
// clang-format on

void oauth2_nginx_log(oauth2_log_sink_t *sink, const char *filename,
		      unsigned long line, const char *function,
		      oauth2_log_level_t level, const char *msg)
{
	// TODO: ngx_err_t?
	ngx_log_error_core(log_level_log2nginx[level],
			   (ngx_log_t *)oauth2_log_sink_ctx_get(sink), 0,
			   "# %s: %s", function, msg);
}

// OAUTH2_NGINX_REQUEST_COPY_HACK

oauth2_nginx_request_context_t *
oauth2_nginx_request_context_init(ngx_http_request_t *r)
{
	// ngx_http_core_srv_conf_t *cscf;
	oauth2_nginx_request_context_t *ctx = NULL;
	oauth2_log_sink_t *log_sink_nginx = NULL;

	// cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

	// TODO: memory allocation failure checks...?
	ctx = oauth2_mem_alloc(sizeof(oauth2_nginx_request_context_t));

	// TODO: get the log level from NGINX...
	oauth2_log_level_t level = OAUTH2_LOG_TRACE1;
	log_sink_nginx =
	    oauth2_log_sink_create(level, oauth2_nginx_log, r->connection->log);

	ctx->log = oauth2_log_init(level, log_sink_nginx);
	ctx->request = oauth2_http_request_init(ctx->log);
	ctx->r = r;

	//_oauth2_nginx_request_copy(ctx);

	oauth2_debug(ctx->log, "created NGINX request context: %p", ctx);

	return ctx;
}

void oauth2_nginx_request_context_free(void *rec)
{
	oauth2_nginx_request_context_t *ctx =
	    (oauth2_nginx_request_context_t *)rec;
	if (ctx) {
		oauth2_debug(ctx->log, "dispose NGINX request context: %p",
			     ctx);
		if (ctx->request)
			oauth2_http_request_free(ctx->log, ctx->request);
		oauth2_log_free(ctx->log);
		oauth2_mem_free(ctx);
	}
}

ngx_int_t oauth2_nginx_http_response_set(oauth2_log_t *log,
					 oauth2_http_response_t *response,
					 ngx_http_request_t *r)
{
	ngx_int_t nrc = NGX_ERROR;
	// ngx_table_elt_t *h = NULL;

	if ((response == NULL) || (r == NULL))
		goto end;

	// oauth2_http_response_headers_loop(log, response,
	//				  oauth2_nginx_response_header_set, r);

	r->headers_out.status =
	    oauth2_http_response_status_code_get(log, response);

	nrc = ngx_http_send_header(r);

end:

	return nrc;
}

// clang-format off
/*
oauth2_cfg_server_callback_funcs_t oauth2_nginx_server_callback_funcs = {
    _oauth2_nginx_env_get_cb,
	_oauth2_nginx_env_set_cb,
    _oauth2_nginx_read_form_post
};
*/
// clang-format on
