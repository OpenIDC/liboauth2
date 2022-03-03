[![Build Status](https://github.com/zmartzone/liboauth2/actions/workflows/build.yml/badge.svg)](https://github.com/zmartzone/liboauth2/actions/workflows/build.yml)
[![Architectures Status](https://github.com/zmartzone/liboauth2/actions/workflows/archs.yml/badge.svg)](https://github.com/zmartzone/liboauth2/actions/workflows/archs.yml)
[![CodeQL Analysis](https://github.com/zmartzone/liboauth2/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/zmartzone/liboauth2/actions/workflows/codeql-analysis.yml)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/zmartzone/liboauth2.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/zmartzone/liboauth2/context:cpp)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/zmartzone/liboauth2.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/zmartzone/liboauth2/alerts/)

# liboauth2
Generic library to build C-based OAuth 2.x and OpenID Connect servers and clients e.g. web-server plugins.

## Overview
- extends [cjose](https://github.com/cisco/cjose) into OAuth 2.x and OpenID Connect specific claims, secrets, and hashes
- adds OAuth 2.x and OpenID Connect protocols by abstracting HTTP requests and responses from web server implementation specifics
- reusable code across other OAuth 2.x and REST related protocols
  e.g. token exchange with endpoint authentication, source token retrieval, target pass settings etc.
- generic code with plugins for Apache, NGINX, and possibly more (e.g. Envoy, HA Proxy, IIS)
- configurable cache backend/size/options per cache element type
- cookie-based session management (i.e. enforce inactivity timeout, expiry)

## Features
- [OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- OAuth 2.0 Resource Owner Password Credentials ([RFC 6749](https://tools.ietf.org/html/rfc6749#section-4.3))
- OAuth 2.0 Token Introspection ([RFC 7662](https://tools.ietf.org/html/rfc7662))
- JWT bearer token validation using JWK, JWKS URI, shared symmetric key, X.509 cert, and RSA public key ([RFC 6750](https://tools.ietf.org/html/rfc6750))
- OAuth 2.0 Authorization Server Metadata ([RFC 8414](https://tools.ietf.org/html/rfc8414))
- Proof Key for Code Exchange (PCKE) by OAuth Public Clients ([RFC 7636](https://tools.ietf.org/html/rfc7636))
- OAuth 2.0 Mutual-TLS (MTLS) Certificate-Bound Access Tokens  ([RFC 8705](https://tools.ietf.org/html/rfc8705))
- OAuth 2.0 Demonstration of Proof-of-Possession (DPoP) at the Application Layer ([Internet-Draft](https://tools.ietf.org/html/draft-ietf-oauth-dpop))
- Amazon ALB [EC key URL based `x-amzn-oidc-data` JWT verification](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html)
- endpoint authentication methods: `client_secret_basic`, `client_secret_post`, [`client_secret_jwt`, `private_key_jwt`](https://tools.ietf.org/html/rfc7523), [TLS client certificate](https://tools.ietf.org/id/draft-ietf-oauth-mtls), and HTTP basic authentication
- configurable cache backends: shared memory, file-based, memcache, and Redis
- retrieving a token from a header, a query parameter, a post parameter, or a cookie
- setting a token as a header, a query parameter, a post parameter, or a cookie
- Apache and NGINX bindings

## Dependencies

liboauth2 depends on the following libraries:
- [`openssl`](https://www.openssl.org/) for SSL and crypto support
- [`libcurl`](https://curl.haxx.se/libcurl/) for HTTP client support
- [`jansson`](http://www.digip.org/jansson/) for JSON parsing
- [`cjose`](https://github.com/cisco/cjose) for JSON Object Signing and Encryption (JOSE) support
- (optional) [`libmemcached`](https://libmemcached.org) for memcache cache backend support
- (optional) [`libhiredis`](https://github.com/redis/hiredis) for Redis cache backend support
- (optional) [`Apache 2.x`](https://httpd.apache.org/) for Apache 2.x bindings support
- (optional) [`NGINX`](https://nginx.org) for NGINX bindings support
- (optional, build time only) [`check`](https://libcheck.github.io/check/) for unit test support

## Support

### Community Support
See [Frequently Asked Questions](https://github.com/zmartzone/liboauth2/wiki) on the Wiki.  
Ask questions in the [Discussions](https://github.com/zmartzone/liboauth2/discussions) tracker.

### Commercial Support
For commercial support contracts, professional services, training, and use-case specific support, contact [ZmartZone IAM](https://www.zmartzone.eu) at:
[sales@zmartzone.eu](mailto:sales@zmartzone.eu)

Disclaimer
----------
*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
