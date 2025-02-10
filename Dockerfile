FROM debian:bookworm

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libssl-dev \
    libjansson-dev \
    libcurl4-openssl-dev \
    apache2 \
    apache2-dev \
    git \
    wget \
    cmake \
    libtool \
    autoconf \
    libcjose-dev \
    automake \
    pkg-config \
    libpcre3-dev \
    libpcre2-8-0 \
    libpcre2-dev

# Copy liboauth2 source code into the container
WORKDIR /opt/src
COPY ./ /opt/src/liboauth2

# Build and install custom liboauth2
WORKDIR /opt/src/liboauth2
RUN ./autogen.sh && \
    ./configure && \
    make && \
    make install

# Update the dynamic linker to prioritize the custom liboauth2
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/liboauth2.conf && ldconfig

# Clone mod_oauth2 repository
WORKDIR /opt/src
RUN git clone https://github.com/OpenIDC/mod_oauth2.git

# Build mod_oauth2 against custom liboauth2
WORKDIR /opt/src/mod_oauth2
RUN ./autogen.sh && \
    ./configure --with-apxs2=/usr/bin/apxs && \
    make && \
    make install

# Ensure Apache loads the custom-built mod_oauth2
RUN echo 'LoadModule oauth2_module /usr/lib/apache2/modules/mod_oauth2.so' >> /etc/apache2/apache2.conf

# Copy Apache config file
COPY ./conf/apache.conf /etc/apache2/sites-available/000-default.conf

# Expose HTTP port
EXPOSE 80

# Start Apache in the foreground
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]