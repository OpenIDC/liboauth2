AC_INIT([liboauth2],[1.4.5.5rc0],[hans.zandbelt@openidc.com])

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

AM_PROG_AR
LT_INIT([dlopen])
AC_PROG_CC

AX_CODE_COVERAGE

PKG_CHECK_MODULES(OPENSSL, openssl)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

PKG_CHECK_MODULES(CURL, libcurl)
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)

PKG_CHECK_MODULES(JANSSON, jansson)
AC_SUBST(JANSSON_CFLAGS)
AC_SUBST(JANSSON_LIBS)

PKG_CHECK_MODULES(CJOSE, cjose)
AC_SUBST(CJOSE_CFLAGS)
AC_SUBST(CJOSE_LIBS)

AC_ARG_WITH([memcache], AS_HELP_STRING([--with-memcache], [build with Memcache cache support [default=autodetect]]),)
if test "x$with_memcache" != "xno"; then
	PKG_CHECK_MODULES([MEMCACHE], [libmemcached >= 1.0], [have_memcache="yes"], [have_memcache="no"])
fi
AM_CONDITIONAL(HAVE_LIBMEMCACHE, [test x"$have_memcache" = "xyes"])
AC_SUBST(MEMCACHE_CFLAGS)
AC_SUBST(MEMCACHE_LIBS)
if test x"$have_memcache" = "xyes"; then
	MEMCACHE_PC=', libmemcached >= 1.0'
fi
AC_SUBST(MEMCACHE_PC)


AC_ARG_WITH([redis], AS_HELP_STRING([--with-redis], [build with Redis cache support [default=autodetect]]),)
if test "x$with_redis" != "xno"; then
	PKG_CHECK_MODULES([HIREDIS], [hiredis], [have_redis="yes"], [have_redis="no"])
fi
AM_CONDITIONAL(HAVE_LIBHIREDIS, [test x"$have_redis" = "xyes"])
AC_SUBST(HIREDIS_CFLAGS)
AC_SUBST(HIREDIS_LIBS)
if test x"$have_redis" = "xyes"; then
	HIREDIS_PC=', hiredis'
fi
AC_SUBST(HIREDIS_PC)

AC_ARG_WITH([apache], AS_HELP_STRING([--with-apache], [build with Apache support [default=autodetect]]),)
AC_ARG_WITH([apxs],
    [AS_HELP_STRING([--with-apxs=PATH/NAME],[path to the apxs binary for Apache [[apxs]]])],
    [AC_SUBST(APXS, $with_apxs)],
    [AC_PATH_PROGS(APXS, [apxs2 apxs])])
if test "x$with_apache" != "xno"; then
	PKG_CHECK_MODULES([APR], [apr-1, apr-util-1], [have_apache="yes"], [have_apache="no"])

	AS_IF([test "x${APXS}" != "x" -a -x "${APXS}"],
	      [AC_MSG_NOTICE([apxs found at $APXS])],
	      [AC_MSG_FAILURE(["apxs not found. Use --with-apxs"])])

	APACHE_CFLAGS="`${APXS} -q CFLAGS` `${APXS} -q EXTRA_CPPFLAGS` -I`${APXS} -q INCLUDEDIR` ${APR_CFLAGS}"
fi
AM_CONDITIONAL(HAVE_APACHE, [test x"$have_apache" = "xyes"])
AC_SUBST(APR_LIBS)
AC_SUBST(APACHE_CFLAGS)

AC_ARG_WITH([nginx], AS_HELP_STRING([--with-nginx=DIR], [build with NGINX support [default=no]]), [have_nginx="yes"], [have_nginx="no"])
if test x"$have_nginx" = "xyes" ; then
	if test ! -d "$withval"; then
 		AC_MSG_ERROR([Could not find NGINX. Please specify the path to the NGINX sources using the --with-nginx=/full/path/to/nginx-<version> option.])
	else
 		NGINX_CFLAGS="-I $withval/src/core -I $withval/src/event -I $withval/src/event/modules -I $withval/src/os/unix -I $withval/objs -I $withval/src/http -I $withval/src/http/v2 -I $withval/src/http/modules"
		NGINX_LIBS=
		CPPFLAGS_SAVE="$CPPFLAGS"
		CPPFLAGS="$NGINX_CFLAGS $CPPFLAGS"
		AC_CHECK_HEADER([nginx.h], [], [have_nginx="no" NGINX_CFLAGS= NGINX_LIBS=])
		CPPFLAGS="$CPPFLAGS_SAVE"
	fi
fi
AM_CONDITIONAL(HAVE_NGINX, [test x"$have_nginx" = "xyes"])
AC_SUBST(NGINX_CFLAGS)
AC_SUBST(NGINX_LIBS)

PKG_CHECK_MODULES([CHECK],
        [check >= 0.9.4],
        [have_check="yes"],
        [   AC_MSG_WARN([Check not found; cannot run unit tests!]);
            [have_check="no"]
        ])
AM_CONDITIONAL(HAVE_CHECK, [test x"$have_check" = "xyes"])
AC_SUBST(CHECK_CFLAGS)
AC_SUBST(CHECK_LIBS)

AC_CONFIG_FILES([
  include/oauth2/version.h
  liboauth2.pc
  liboauth2_apache.pc
  liboauth2_nginx.pc
  Makefile
])

AC_OUTPUT
