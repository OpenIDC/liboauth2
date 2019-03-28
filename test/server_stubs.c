#ifdef HAVE_APACHE
#include <oauth2/apache.h>

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
#include <oauth2/nginx.h>

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
			const char *fmt, ...)
{
}
#endif
