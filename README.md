# liboauth2
Generic library that can be used to build OAuth 2.0 and OpenID Connect C-based servers and clients e.g. web-server plugins.

## Features

- extends [cjose](https://github.com/cisco/cjose) into OAuth 2.0 and OpenID Connect specific claims, secrets and hashes
- adds OAuth 2.0 / OpenID Connect protocols by abstracting HTTP requests/responses from web server implementation specifics
- reusable code across for other OAuth 2.0 (and REST) related protocols
  e.g. token exchange with endpoint authentication, source token retrieval, target pass settings etc.
- generic code with plugins for Apache, NGINX and possibly more (e.g. Envoy, HA Proxy, IIS)
- cache backend/size/options per cache element type (i.e. no longer a single flat shared backend/storage/namespace)
- configurable cache key hashing algorithm
- shm: support configurable key sizes (ie. storage)

## Features
- OAuth 2.0 Token Introspection [https://tools.ietf.org/html/rfc7662](https://tools.ietf.org/html/rfc7662)
- JWT bearer token validation using: JWK, JWKS URI, shared symmetric key, X.509 cert, RSA public key
- OAuth 2.0 Authorization Server Metadata [https://tools.ietf.org/html/rfc8414](https://tools.ietf.org/html/rfc8414)
- Amazon ALB [EC key URL based `x-amzn-oidc-data` JWT verification](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html)
- endpoint authentication methods: `client_secret_basic`, `client_secret_post`, [`client_secret_jwt`, `private_key_jwt`](https://tools.ietf.org/html/rfc7523), [TLS client certificate](https://tools.ietf.org/id/draft-ietf-oauth-mtls) and HTTP basic authentication
- configurable cache backends: shared memory, file-based, memcache and Redis
- retrieving a token from a header, a query parameter, a post parameter or a cookie
- setting a token as a header, a query parameter, a post parameter or a cookie
- Apache and NGINX bindings

## Dependencies

liboauth2 has the following dependencies:
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

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/zmartzone/liboauth2/wiki](https://github.com/zmartzone/liboauth2/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@zmartzone.eu](mailto:sales@zmartzone.eu)  


Disclaimer
----------
*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
