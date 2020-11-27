#ifdef HAVE_APACHE
#include <apr_lib.h>
#include <oauth2/apache.h>

static char *substring_conf(apr_pool_t *p, const char *start, int len,
			    char quote)
{
	char *result = apr_palloc(p, len + 1);
	char *resp = result;
	int i;

	for (i = 0; i < len; ++i) {
		if (start[i] == '\\' &&
		    (start[i + 1] == '\\' || (quote && start[i + 1] == quote)))
			*resp++ = start[++i];
		else
			*resp++ = start[i];
	}

	*resp++ = '\0';
#if RESOLVE_ENV_PER_TOKEN
	return (char *)ap_resolve_env(p, result);
#else
	return result;
#endif
}

AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line)
{
	const char *str = *line, *strend;
	char *res;
	char quote;

	while (apr_isspace(*str))
		++str;

	if (!*str) {
		*line = str;
		return "";
	}

	if ((quote = *str) == '"' || quote == '\'') {
		strend = str + 1;
		while (*strend && *strend != quote) {
			if (*strend == '\\' && strend[1] &&
			    (strend[1] == quote || strend[1] == '\\')) {
				strend += 2;
			} else {
				++strend;
			}
		}
		res = substring_conf(p, str + 1, strend - str - 1, quote);

		if (*strend == quote)
			++strend;
	} else {
		strend = str;
		while (*strend && !apr_isspace(*strend))
			++strend;

		res = substring_conf(p, str, strend - str, 0);
	}

	while (apr_isspace(*strend))
		++strend;
	*line = strend;
	return res;
}

AP_DECLARE(char *) ap_getword_conf_nc(apr_pool_t *p, char **line)
{
	return ap_getword_conf(p, (const char **)line);
}

AP_DECLARE(int) ap_should_client_block(request_rec *r)
{
	return 0;
}

AP_DECLARE(long)
ap_get_client_block(request_rec *r, char *buffer, apr_size_t bufsiz)
{
	return 0;
}

AP_DECLARE(const char *) ap_get_server_name(request_rec *r)
{
	return "www.example.com";
}

AP_DECLARE(const char *) ap_get_server_name_for_url(request_rec *r)
{
	return "www.example.com";
}

AP_DECLARE(int) ap_setup_client_block(request_rec *r, int read_policy)
{
	return 0;
}

AP_DECLARE(const char *) ap_auth_type(request_rec *r)
{
	return "oauth2";
}

AP_DECLARE(const char *) ap_auth_name(request_rec *r)
{
	return "oauth2";
}

const char *ap_run_http_scheme(const request_rec *r)
{
	return "https";
}
#endif

#ifdef HAVE_NGINX
#undef LF
#undef CR
#undef CRLF
#include <oauth2/mem.h>
#include <oauth2/nginx.h>

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
			const char *fmt, ...)
{
}

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log)
{
	ngx_pool_t *pool = (ngx_pool_t *)oauth2_mem_alloc(size);
	return pool;
}

void ngx_destroy_pool(ngx_pool_t *pool)
{
	oauth2_mem_free(pool);
}

void *ngx_palloc(ngx_pool_t *pool, size_t size)
{
	void *p = (void *)oauth2_mem_alloc(size);
	return p;
}

void *ngx_list_push(ngx_list_t *l)
{
	void *elt;
	ngx_list_part_t *last;

	last = l->last;

	if (last->nelts == l->nalloc) {

		/* the last part is full, allocate a new list part */

		last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
		if (last == NULL) {
			return NULL;
		}

		last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
		if (last->elts == NULL) {
			return NULL;
		}

		last->nelts = 0;
		last->next = NULL;

		l->last->next = last;
		l->last = last;
	}

	elt = (char *)last->elts + l->size * last->nelts;
	last->nelts++;

	return elt;
}

#endif
