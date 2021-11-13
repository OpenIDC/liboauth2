#FROM ubuntu:trusty
FROM ubuntu:bionic
MAINTAINER hans.zandbelt@zmartzone.eu

RUN apt-get update && apt-get install -y pkg-config make gcc gdb lcov valgrind vim curl wget
RUN apt-get update && apt-get install -y autoconf automake libtool
RUN apt-get update && apt-get install -y libssl-dev libjansson-dev libcurl4-openssl-dev check
RUN apt-get update && apt-get install -y apache2-dev
#RUN apt-get update && apt-get install -y libcjose-dev
RUN apt-get update && apt-get install -y libpcre3-dev zlib1g-dev

ENV NGINX_VERSION 1.16.1
WORKDIR /root
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
RUN tar zxvf nginx-${NGINX_VERSION}.tar.gz
RUN ln -s nginx-${NGINX_VERSION} nginx
RUN cd /root/nginx && ./configure --with-debug

#ENV FLAVOR trusty
ENV FLAVOR bionic
ENV CJOSE_VERSION 0.6.1.5

ENV CJOSE_PKG libcjose0_${CJOSE_VERSION}-1~${FLAVOR}+1_arm64.deb
RUN curl -s -L -o ~/${CJOSE_PKG} https://mod-auth-openidc.org/download/${CJOSE_PKG}
RUN dpkg -i ~/${CJOSE_PKG}
ENV CJOSE_PKG libcjose-dev_${CJOSE_VERSION}-1~${FLAVOR}+1_arm64.deb
RUN curl -s -L -o ~/${CJOSE_PKG} https://mod-auth-openidc.org/download/${CJOSE_PKG}
RUN dpkg -i ~/${CJOSE_PKG}
RUN apt-get update && apt-get install -y -f

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
