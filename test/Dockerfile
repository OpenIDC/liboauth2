FROM ubuntu:jammy

RUN apt-get update && apt-get install -y pkg-config make gcc gdb lcov valgrind vim curl wget
RUN apt-get update && apt-get install -y autoconf automake libtool
RUN apt-get update && apt-get install -y libssl-dev libjansson-dev libcurl4-openssl-dev check
RUN apt-get update && apt-get install -y apache2-dev
RUN apt-get update && apt-get install -y libpcre3-dev zlib1g-dev

ENV NGINX_VERSION 1.18.0
WORKDIR /root
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
RUN tar zxvf nginx-${NGINX_VERSION}.tar.gz
RUN ln -s nginx-${NGINX_VERSION} nginx
RUN cd /root/nginx && ./configure --with-debug

RUN apt-get update && apt-get install -y libpcre2-dev libpcre2-8-0
RUN apt-get update && apt-get install -y libcjose-dev libcjose0
RUN apt-get update && apt-get install -y libmemcached-dev memcached
RUN apt-get update && apt-get install -y libhiredis-dev redis-server

ENV SRCDIR /root/liboauth2
RUN mkdir ${SRCDIR}
WORKDIR ${SRCDIR}

ENV LD_LIBRARY_PATH ${SRCDIR}/.libs
ENV CK_FORK "no"

RUN sed -i "s/bind .*/bind 127.0.0.1/g" /etc/redis/redis.conf
RUN echo "requirepass foobared" >> /etc/redis/redis.conf

RUN echo "#!/bin/sh" >> ./start.sh
RUN echo "service memcached start" >> ./start.sh
RUN echo "service redis-server start" >> ./start.sh
RUN chmod a+x ./start.sh

COPY . ${SRCDIR}

ARG CONFIGURE_ARGS

RUN ./autogen.sh
RUN ./configure \
	CFLAGS="-g -O0 -I/usr/include/apache2" \
	LDFLAGS="-lrt" \
	--with-nginx=/root/nginx \
	${CONFIGURE_ARGS}
RUN make all
RUN make check_liboauth2
