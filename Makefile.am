ACLOCAL_AMFLAGS=-I m4

EXTRA_DIST = autogen.sh ChangeLog README.md LICENSE

#
# generic
#

AM_CPPFLAGS = -Wall -Werror -Wno-error=deprecated-declarations -I${srcdir}/include -I${srcdir}/src @JANSSON_CFLAGS@ @OPENSSL_CFLAGS@
AM_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = --coverage

LDADD = @JANSSON_LIBS@ @OPENSSL_LIBS@
LDADD += $(CODE_COVERAGE_LIBS)

#
# headers
#

includesubdir = $(includedir)/oauth2

includesub_HEADERS = \
	include/oauth2/cache.h \
	include/oauth2/http.h \
	include/oauth2/ipc.h \
	include/oauth2/jose.h \
	include/oauth2/log.h \
	include/oauth2/mem.h \
	include/oauth2/proto.h \
	include/oauth2/oauth2.h \
	include/oauth2/openidc.h \
	include/oauth2/session.h \
	include/oauth2/cfg.h \
	include/oauth2/util.h \
	include/oauth2/version.h

if HAVE_LIBJQ
includesub_HEADERS += \
	include/oauth2/jq.h
endif

#
# liboauth
#

lib_LTLIBRARIES = liboauth2.la

liboauth2_la_pkgconfigdir = $(libdir)/pkgconfig
liboauth2_la_pkgconfig_DATA = liboauth2.pc

liboauth2_la_CFLAGS = @CURL_CFLAGS@ @CJOSE_CFLAGS@ @PCRE2_CFLAGS@
liboauth2_la_LIBADD = @CURL_LIBS@ @CJOSE_LIBS@ @PCRE2_LIBS@

liboauth2_la_SOURCES = \
	src/version.c \
	src/mem.c \
	src/log.c \
	src/util_int.h \
	src/util.c \
	src/cfg_int.h \
	src/cfg/cfg.c \
	src/cfg/auth.c \
	src/cfg/source.c \
	src/cfg/cache_cfg.c \
	src/cfg/verify.c \
	src/cfg/target.c \
	src/cfg/proto_cfg.c \
	src/cfg/openidc_cfg.c \
	src/cfg/session_cfg.c \
	src/ipc.c \
	src/cache_int.h \
	src/cache/shm.c \
	src/cache/file.c \
	src/jose_int.h \
	src/jose.c \
	src/http.c \
	src/proto.c \
	src/oauth2_int.h \
	src/oauth2.c \
	src/dpop.c \
	src/session.c \
	src/openidc_int.h \
	src/openidc/provider.c \
	src/openidc/resolver.c \
	src/openidc/client.c \
	src/openidc/state.c \
	src/openidc/openidc.c

if HAVE_LIBJQ
AM_CPPFLAGS += -DHAVE_LIBJQ
liboauth2_la_CFLAGS += @JQ_CFLAGS@
liboauth2_la_LIBADD += @JQ_LIBS@
liboauth2_la_SOURCES += src/jq.c
endif

#
# cache
#

noinst_LTLIBRARIES = liboauth2_cache.la
liboauth2_la_LIBADD += liboauth2_cache.la
liboauth2_cache_la_SOURCES = src/cache.c
liboauth2_cache_la_CPPFLAGS = $(AM_CPPFLAGS)
liboauth2_cache_la_CFLAGS = @CURL_CFLAGS@ @CJOSE_CFLAGS@ @PCRE2_CFLAGS@

if HAVE_LIBMEMCACHE
liboauth2_cache_la_CPPFLAGS += -DHAVE_LIBMEMCACHE
liboauth2_la_LIBADD += liboauth2_memcache.la
noinst_LTLIBRARIES += liboauth2_memcache.la 
liboauth2_memcache_la_SOURCES = src/cache/memcache.c
liboauth2_memcache_la_CFLAGS = @MEMCACHE_CFLAGS@
liboauth2_memcache_la_LIBADD = @MEMCACHE_LIBS@
endif

if HAVE_LIBHIREDIS
liboauth2_cache_la_CPPFLAGS += -DHAVE_LIBHIREDIS
liboauth2_la_LIBADD += liboauth2_redis.la
noinst_LTLIBRARIES += liboauth2_redis.la
liboauth2_redis_la_SOURCES = src/cache/redis.c
liboauth2_redis_la_CFLAGS = @HIREDIS_CFLAGS@
liboauth2_redis_la_LIBADD = @HIREDIS_LIBS@
endif

#
# liboauth2_apache
#

if HAVE_APACHE
lib_LTLIBRARIES += liboauth2_apache.la

liboauth2_apache_la_pkgconfigdir = $(libdir)/pkgconfig
liboauth2_apache_la_pkgconfig_DATA = liboauth2_apache.pc

liboauth2_apache_la_CPPFLAGS = $(AM_CPPFLAGS) -DHAVE_APACHE
liboauth2_apache_la_CFLAGS = @APACHE_CFLAGS@ @PCRE2_CFLAGS@
liboauth2_apache_la_LIBADD = liboauth2.la @APR_LIBS@ @JANSSON_LIBS@

includesub_HEADERS += \
	include/oauth2/apache.h

liboauth2_apache_la_SOURCES = \
	src/server/apache.c
endif

#
# liboauth2_nginx
#

if HAVE_NGINX
lib_LTLIBRARIES += liboauth2_nginx.la

liboauth2_nginx_la_pkgconfigdir = $(libdir)/pkgconfig
liboauth2_nginx_la_pkgconfig_DATA = liboauth2_nginx.pc

liboauth2_nginx_la_CPPFLAGS = $(AM_CPPFLAGS) -DHAVE_NGINX
liboauth2_nginx_la_CFLAGS = @NGINX_CFLAGS@ @PCRE2_CFLAGS@
liboauth2_nginx_la_LIBADD = liboauth2.la @NGINX_LIBS@ @JANSSON_LIBS@

includesub_HEADERS += \
	include/oauth2/nginx.h

liboauth2_nginx_la_SOURCES = \
	src/server/nginx.c
endif

#
# check
#

if HAVE_CHECK

TESTS = check_liboauth2
check_PROGRAMS = $(TESTS)

check_liboauth2_CPPFLAGS = $(liboauth2_cache_la_CPPFLAGS)
check_liboauth2_CFLAGS = @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @CJOSE_CFLAGS@ @PCRE2_CFLAGS@ @JQ_CFLAGS@ @CHECK_CFLAGS@
check_liboauth2_LDADD = liboauth2.la
if HAVE_APACHE
check_liboauth2_CPPFLAGS += $(liboauth2_apache_la_CPPFLAGS)
check_liboauth2_CFLAGS += $(liboauth2_apache_la_CFLAGS)
check_liboauth2_LDADD += liboauth2_apache.la ${liboauth2_apache_la_LIBADD}
endif
if HAVE_NGINX
check_liboauth2_CPPFLAGS += $(liboauth2_nginx_la_CPPFLAGS)
check_liboauth2_CFLAGS += $(liboauth2_nginx_la_CFLAGS)
check_liboauth2_LDADD += liboauth2_nginx.la
endif
check_liboauth2_LDADD += @OPENSSL_LIBS@ @CURL_LIBS@ @CJOSE_LIBS@ @PCRE2_LIBS@ @CHECK_LIBS@

check_liboauth2_SOURCES = \
	test/check_liboauth2.h \
	test/check_liboauth2.c \
	test/check_version.c \
	test/check_mem.c \
	test/check_log.c \
	test/check_cfg.c \
	test/check_util.c \
	test/check_ipc.c \
	test/check_cache.c \
	test/check_jose.c \
	test/check_http.c \
	test/check_proto.c \
	test/check_oauth2.c \
	test/check_openidc.c \
	test/server_stubs.c \
	test/provider.json \
	test/client.json

if HAVE_LIBJQ
check_liboauth2_SOURCES += \
	test/check_jq.c
endif
if HAVE_APACHE
check_liboauth2_SOURCES += \
	test/check_apache.c
endif
if HAVE_NGINX
check_liboauth2_SOURCES += \
	test/check_nginx.c
endif

endif


#@CODE_COVERAGE_RULES@


clang-format:
	clang-format -style=file -i `find . -name *.[ch]`

test: check

TAG=liboauth2/test

docker: clean
	docker build --progress plain -f test/Dockerfile . -t $(TAG)
	
docker-check: docker
	docker run -it --rm $(TAG):latest /bin/bash -c "./start.sh && make check"

docker-coverage: clean
	docker build --build-arg CONFIGURE_ARGS="--enable-code-coverage" -f test/Dockerfile . -t $(TAG)
	docker run -it --rm $(TAG):latest /bin/bash -c "./start.sh && make check-code-coverage"

docker-valgrind: docker
	docker run -it --rm -e CK_FORK=no $(TAG):latest /bin/bash -c "./start.sh && /usr/bin/valgrind --leak-check=full --show-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes .libs/check_liboauth2"
	
docker-valgrind-%: docker
	docker run -it --rm -e CK_FORK=no -e CK_RUN_SUITE=${subst docker-valgrind-,,$@} $(TAG):latest /bin/bash -c "./start.sh && /usr/bin/valgrind --leak-check=full --show-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes .libs/check_liboauth2"

docker-gdb: docker
	docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm -e CK_FORK=no $(TAG):latest /bin/bash -c "./start.sh && /usr/bin/gdb .libs/check_liboauth2"

docker-gdb-%: docker
	docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm -e CK_FORK=no -e CK_RUN_SUITE=${subst docker-gdb-,,$@} $(TAG):latest /bin/bash -c "./start.sh && /usr/bin/gdb .libs/check_liboauth2"
