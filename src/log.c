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

// need this at the top for vasprintf
#include "oauth2/log.h"
#include "oauth2/mem.h"
#include "util_int.h"
#include <stdarg.h>
#include <stdlib.h>

typedef struct oauth2_log_sink_t {
	oauth2_log_level_t level;
	oauth2_log_function_t callback;
	void *ctx;
} oauth2_log_sink_t;

// note this is fastest, but must maintain the order of the enum...
static const char *_oauth2_log_level2str[] = {"ERR", "WRN", "NOT", "INF",
					      "DBG", "TR1", "TR2"};

typedef struct oauth2_log_sink_list_elem_t {
	oauth2_log_sink_t *sink;
	struct oauth2_log_sink_list_elem_t *next;
} oauth2_log_sink_list_elem_t;

typedef struct oauth2_log_sink_list_t {
	oauth2_log_sink_list_elem_t *first;
	oauth2_log_sink_list_elem_t *last;
} oauth2_log_sink_list_t;

typedef struct oauth2_log_t {
	oauth2_log_sink_list_t sinks;
} oauth2_log_t;

oauth2_log_sink_t *oauth2_log_sink_create(oauth2_log_level_t level,
					  oauth2_log_function_t callback,
					  void *ctx)
{
	oauth2_log_sink_t *sink = oauth2_mem_alloc(sizeof(oauth2_log_sink_t));
	sink->callback = callback;
	sink->level = level;
	sink->ctx = ctx;
	return sink;
}

void *oauth2_log_sink_ctx_get(oauth2_log_sink_t *sink)
{
	return sink->ctx;
}

oauth2_log_function_t oauth2_log_sink_callback_get(oauth2_log_sink_t *sink)
{
	return sink->callback;
}

void oauth2_log_sink_add(oauth2_log_t *log, oauth2_log_sink_t *add)
{
	oauth2_log_sink_list_elem_t *ptr =
	    (oauth2_log_sink_list_elem_t *)oauth2_mem_alloc(
		sizeof(oauth2_log_sink_list_elem_t));
	;
	ptr->sink = add;
	ptr->next = NULL;

	if (log->sinks.first == NULL) {
		log->sinks.first = ptr;
		log->sinks.last = ptr;
	} else {
		log->sinks.last->next = ptr;
	}
}

void oauth2_log_sink_level_set(oauth2_log_sink_t *sink,
			       oauth2_log_level_t level)
{
	sink->level = level;
}

static void oauth2_log_std(FILE *std, oauth2_log_sink_t *sink,
			   const char *filename, unsigned long line,
			   const char *function, oauth2_log_level_t level,
			   const char *msg)
{
	// TODO: make a print-to-string function for this generic prefix?
	fprintf(std, "[%s:%lu:%s:%s] %s\n", filename, line, function,
		_oauth2_log_level2str[level], msg);
}

static void oauth2_log_std_err(oauth2_log_sink_t *sink, const char *filename,
			       unsigned long line, const char *function,
			       oauth2_log_level_t level, const char *msg)
{
	oauth2_log_std(stderr, sink, filename, line, function, level, msg);
}

static void oauth2_log_std_out(oauth2_log_sink_t *sink, const char *filename,
			       unsigned long line, const char *function,
			       oauth2_log_level_t level, const char *msg)
{
	oauth2_log_std(stdout, sink, filename, line, function, level, msg);
}

oauth2_log_sink_t oauth2_log_sink_stderr = {OAUTH2_LOG_INFO, oauth2_log_std_err,
					    NULL};

oauth2_log_sink_t oauth2_log_sink_stdout = {OAUTH2_LOG_INFO, oauth2_log_std_out,
					    NULL};

// API

#ifdef _MSC_VER

int vasprintf(char **strp, const char *fmt, va_list ap)
{
	// _vscprintf tells you how big the buffer needs to be
	int len = _vscprintf(fmt, ap);
	if (len == -1) {
		return -1;
	}
	size_t size = (size_t)len + 1;
	char *str = malloc(size);
	if (!str) {
		return -1;
	}

	// _vsprintf_s is the "secure" version of vsprintf
	int r = vsprintf_s(str, len + 1, fmt, ap);
	if (r == -1) {
		free(str);
		return -1;
	}
	*strp = str;
	return r;
}

#endif

void oauth2_log(oauth2_log_t *log, const char *filename, unsigned long line,
		const char *function, oauth2_log_level_t level, const char *fmt,
		...)
{
	va_list ap;
	oauth2_log_sink_list_elem_t *ptr;
	char *msg = NULL;
	int rc = 0;

	if ((log == NULL) || (log->sinks.first == NULL) || (fmt == NULL))
		goto end;

	va_start(ap, fmt);
	rc = vasprintf(&msg, fmt, ap);
	// TODO: can't get this to work...?
	// rc = oauth2_sprintf(&msg, fmt, ap);
	(void)rc;
	va_end(ap);

	if (msg) {
		for (ptr = log->sinks.first; ptr != NULL; ptr = ptr->next) {
			if (level > ptr->sink->level)
				continue;
			ptr->sink->callback(ptr->sink, filename, line, function,
					    level, msg);
		}
		// TODO: can't get this to work...?
		// oauth2_mem_free(msg);
		free(msg);
	}

end:

	return;
}

oauth2_log_t *oauth2_log_init(oauth2_log_level_t level, oauth2_log_sink_t *sink)
{
	oauth2_log_t *log =
	    (oauth2_log_t *)oauth2_mem_alloc(sizeof(oauth2_log_t));
	if (log == NULL)
		goto end;

	log->sinks.first = NULL;
	log->sinks.last = NULL;
	oauth2_log_sink_add(log,
			    (sink != NULL) ? sink : &oauth2_log_sink_stderr);
	log->sinks.first->sink->level = level;

end:

	return log;
}

void oauth2_log_free(oauth2_log_t *log)
{
	oauth2_log_sink_list_elem_t *ptr = NULL;

	if (log == NULL)
		goto end;

	while ((ptr = log->sinks.first)) {
		log->sinks.first = log->sinks.first->next;
		if ((ptr->sink != &oauth2_log_sink_stderr) &&
		    (ptr->sink != &oauth2_log_sink_stdout))
			oauth2_mem_free(ptr->sink);
		oauth2_mem_free(ptr);
	}
	log->sinks.last = NULL;
	oauth2_mem_free(log);

end:

	return;
}

/*
 static int oauth2_log_level2aplog[] = {
 APLOG_ERR,
 APLOG_WARNING,
 APLOG_NOTICE,
 APLOG_INFO,
 APLOG_DEBUG,
 APLOG_TRACE1
 };

 void oauth2_log_backend_ap_log_rerror(void *log_log, const char *filename,
 unsigned long line, const char *function, oauth2_log_level_t level, const char
 *fmt, ...) {
 request_rec *r = (request_rec *)log_log;
 ap_log_rerror(filename, line, APLOG_MODULE_INDEX,
 oauth2_log_level2aplog[level], 0, r,"%s: %s", function, apr_psprintf(r->pool,
 fmt, ##__VA_ARGS__))
 }
 */
