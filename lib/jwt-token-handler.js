'use strict';

const _ = require('lodash');
const BearerTokenError = require('./errors/bearer-token-error')
const Jwt = require('jsonwebtoken');
const JwksResolver = require('./jwks-resolver');
const logger = require('debug')('oauth2-jwt-bearer');

const methods = {
  HEADER: 'HEADER',
  QUERY: 'QUERY',
  FORM_BODY: 'FORM_BODY'
}

class JwtTokenHandler {

  static get methods() {
    return methods;
  }

  constructor(options) {

    if (!options) {
      throw new TypeError('options is a required argument to verify a token');
    }

    // clone to mutate
    options = _.clone(options);

    if (!options.issuer) {
      throw new TypeError('options.issuer is a required argument to verify a token');
    }

    if (!options.audience) {
      throw new TypeError('options.audience is a required argument to verify a token');
    }

    if (!options.jwks && !options.jwksUrl) {
      throw new TypeError('options.jwks or options.jwksUrl is a required argument to verify a token');
    }

    if (options.scopes) {
      options.scopes = _.isArray(options.scopes) ? options.scopes : [options.scopes]
    };

    this._options = _.defaults(options, {
      realm: options.audience,
      // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16
      scopesClaimName: 'scope',
      clockTolerance: 5,
      algorithms: ['RS256', 'RS384', 'RS512'],
      methods: [
        'HEADER',
        'QUERY',
        'FORM_BODY'
      ]
    });

    this._keyResolver = new JwksResolver(options.jwks, {
      jwksUri: options.jwksUrl,
      strictSsl: true,
      rateLimit: true,
      cache: true
    });
  }

  get issuer() {
    return this._options.issuer;
  }

  get audience() {
    return this._options.audience;
  }

  get issuer() {
    return this._options.issuer;
  }

  get realm() {
    return this._options.realm;
  }

  get scopes() {
    return this._options.scopes;
  }

  get scopesClaimName() {
    return this._options.scopesClaimName;
  }

  get clockTolerance() {
    return this._options.clockTolerance;
  }

  get algorithms() {
    return this._options.algorithms;
  }

  getSigningKeys(cb) {
    return this._keyResolver.getSigningKeys()
      .then(keys => {
        return cb(null, keys);
      })
      .catch(err => {
        return cb(err);
      })
  }

  verifyToken(token, options, cb) {
    const self = this;

    if (typeof options === 'function') {
      cb = options;
      options = {};
    }

    options = _.clone(options);
    // merge scopes
    if (options.scopes) {
      options.scopes = _.union(
        _.isArray(options.scopes) ? options.scopes : [options.scopes],
        this.scopes
      );
    }
    options = _.defaults(options, this._options);

    const decodedJwt = Jwt.decode(token, {complete: true});

    if (!_.isObject(decodedJwt)) {
      return cb(new BearerTokenError({
        realm: options.realm,
        errorCode: 'invalid_token',
        description: 'The token is not a valid JSON Web Token (JWT)',
        uri: 'https://tools.ietf.org/html/rfc7519'
      }));
    }

    logger('Verifying JWT bearer token => %j', decodedJwt);

    if (!_.isObject(decodedJwt.header)) {
      return cb(new BearerTokenError({
        realm: options.realm,
        errorCode: 'invalid_token',
        description: 'The token must specify a JOSE header',
        uri: 'https://tools.ietf.org/html/rfc7519#section-5'
      }));
    }

    if (!_.isString(decodedJwt.header.alg)) {
      return cb(new BearerTokenError({
        realm: options.realm,
        errorCode: 'invalid_token',
        description: 'The token must specify an "alg" header parameter',
        uri: 'https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-03#section-3.1'
      }));
    }

    if (decodedJwt.header.alg === 'none') {
      return cb(new BearerTokenError({
        realm: options.realm,
        errorCode: 'invalid_token',
        description: 'The token must specify a valid signature algorithm',
      }));
    }

    if (!options.algorithms.includes(decodedJwt.header.alg)) {
      return cb(new BearerTokenError({
        realm: options.realm,
        errorCode: 'invalid_token',
        description: 'The token must specify a valid signature algorithm',
      }));
    }

    if (!_.isString(decodedJwt.header.kid)) {
      return cb(new BearerTokenError({
        realm: options.realm,
        errorCode: 'invalid_token',
        description: 'The token must specify a "kid" (key ID) header parameter',
        uri: 'https://tools.ietf.org/html/rfc7519'
      }));
    }

    self._keyResolver.getSigningKey(decodedJwt.header.kid)
      .then(key => {
        Jwt.verify(
          token,
          key.publicKey || key.rsaPublicKey,
          // we will validate these claims later
          _.omit(options, ['issuer', 'audience']),
          function(err, claims) {
            if (err) {
              logger('Unable to verify token due to error %s', err.message);
              if (err instanceof Jwt.TokenExpiredError) {
                return cb(new BearerTokenError({
                  realm: options.realm,
                  errorCode: 'invalid_token',
                  description: 'The token is expired',
                  uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.4'
                }));
              } else if (err instanceof Jwt.NotBeforeError) {
                return cb(new BearerTokenError({
                  realm: options.realm,
                  errorCode: 'invalid_token',
                  description: 'The token is valid in the future',
                  uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.5'
                }));
              } else {
                return cb(new BearerTokenError({
                  realm: options.realm,
                  errorCode: 'invalid_token',
                  description: 'The token is not valid',
                  uri: 'https://tools.ietf.org/html/rfc7519'
                }));
              }
            }

            claims.hasScopes = function(scopes) {
              if (scopes) {
                scopes = _.isArray(scopes) ? scopes : [scopes];
                const grantedScopes = _.intersectionBy(claims[options.scopesClaimName], scopes);
                return (scopes.length === grantedScopes.length);
              }
              return false;
            };

            if (claims.iss !== options.issuer) {
              logger('Token has invalid issuer (token=%s expected=%s)', claims.iss, options.issuer);
              return cb(new BearerTokenError({
                realm: options.realm,
                errorCode: 'invalid_token',
                description: 'The token issuer is not trusted',
                uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.1'
              }));
            }

            if (claims.aud !== options.audience) {
              logger('Token has invalid audience (token=%s expected=%s)', claims.aud, options.audience);
              return cb(new BearerTokenError({
                realm: options.realm,
                errorCode: 'invalid_token',
                description: 'The token is not valid for audience ' + options.audience,
                uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.3'
              }));
            }

            if (options.scopes && !claims.hasScopes(options.scopes)) {
              logger('Token does not have required scopes (token=%s expected=%s)',
                claims[options.scopesClaimName] ? claims[options.scopesClaimName].join(' ') : '', options.scopes.join(' '));
              return cb(new BearerTokenError({
                realm: options.realm,
                errorCode: 'insufficient_scope',
                scopes: options.scopes,
                description: 'Insufficient scope for this resource',
                uri: 'https://tools.ietf.org/html/rfc6750#section-3'
              }));
            }

            logger('Token was successfully verified => %j', claims);
            return cb(null, claims);
          }
        );
      })
      .catch(err => {
        logger('Unable to resolve key for kid=%s due to error %s', decodedJwt.header.kid, err.message);
        return cb(new BearerTokenError({
          realm: options.realm,
          errorCode: 'invalid_token',
          description: 'Unable to resolve key for token signature'
        }));
      })
  }

  verifyRequest(req, options, cb) {
    let bearerHeader = false;
    var token;

    if (typeof options === 'function') {
      cb = options;
      options = {};
    }

    options = _.defaults(_.clone(options), this._options);

    if (options.methods.includes('HEADER') && req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
          bearerHeader = true;
        }
      } else {
        return cb(new BearerTokenError({
          realm: options.realm,
          errorCode: 'invalid_request',
          description: 'Request must specify authorization header with "Bearer" scheme and access token',
          uri: 'https://tools.ietf.org/html/rfc6750#section-2.1'
        }));
      }
    }

    if (options.methods.includes('QUERY') && req.query && req.query.access_token) {
      if (token && bearerHeader) {
        return cb(new BearerTokenError({
          realm: options.realm,
          errorCode: 'invalid_request',
          description: 'Request cannot have an access token in both authorization header and query parameter',
          uri: 'https://tools.ietf.org/html/rfc6750#section-2.3'
        }));
      }
      token = req.query.access_token;
    }

    if (options.methods.includes('FORM_BODY') && req.headers && req.headers['content-type'] === 'application/x-www-form-urlencoded' &&
      req.body && req.body.access_token && req.method !== 'GET') {

      if (token) {
        if (bearerHeader) {
          return cb(new BearerTokenError({
            realm: options.realm,
            errorCode: 'invalid_request',
            description: 'Request cannot have an access token in both authorization header and form body parameter',
            uri: 'https://tools.ietf.org/html/rfc6750#section-2.2'
          }));
        } else {
          return cb(new BearerTokenError({
            realm: options.realm,
            errorCode: 'invalid_request',
            description: 'Request cannot have an access token in both query and form body parameter',
            uri: 'https://tools.ietf.org/html/rfc6750#section-2.2'
          }));
        }
      }
      token = req.body.access_token;
    }

    if (!token) {
      let builder = [];
      if (options.methods.includes('HEADER')) {
        builder.push('authorization header');
      }
      if (options.methods.includes('QUERY')) {
        builder.push('query parameter');
      }
      if (options.methods.includes('FORM_BODY')) {
        builder.push('form body parameter');
      }

      return cb(new BearerTokenError({
        realm: options.realm,
        errorCode: 'invalid_request',
        description: 'Request must specify an access token via ' +
          builder.join(', ').replace(/, ([^,]*)$/, ' or $1'),
        uri: 'https://tools.ietf.org/html/rfc6750'
      }));
    }

    return this.verifyToken(token, options, cb);
  }
};

module.exports = JwtTokenHandler;
