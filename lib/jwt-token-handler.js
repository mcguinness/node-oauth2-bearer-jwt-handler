'use strict';

const _ = require('lodash');
const BearerTokenError = require('./errors/bearer-token-error')
const Jwt = require('jsonwebtoken');
const jwksResolver = require('./jwks-resolver');
const logger = require('debug')('oauth2-jwt-bearer');


function JwtTokenHandler(options, verify) {
  var self = this;

  if (!options.issuer) {
    throw new TypeError('options.issuer is a required argument to verify a token');
  }
  this._issuer = options.issuer;

  if (!options.audience) {
    throw new TypeError('options.audience is a required argument to verify a token');
  }
  this._audience = options.audience;
  this._realm = options.realm || options.audience

  this._scopeClaimName = options.scopeClaimName || 'scp';

  if (!options.jwks && !options.jwksUrl) {
    throw new TypeError('options.jwks or options.jwksUrl is a required argument to verify a token');
  }

  this._keyResolver = jwksResolver(options.jwks || options.jwksUrl, {
    strictSsl: true,
    rateLimit: true,
    cache: true
  });
};

Object.defineProperty(JwtTokenHandler.prototype, 'issuer', {
  get: function() {
    return this._issuer;
  }
});

Object.defineProperty(JwtTokenHandler.prototype, 'audience', {
  get: function() {
    return this._audience;
  }
});

Object.defineProperty(JwtTokenHandler.prototype, 'realm', {
  get: function() {
    return this._realm;
  }
});

Object.defineProperty(JwtTokenHandler.prototype, 'scopeClaimName', {
  get: function() {
    return this._scopeClaimName;
  }
});

JwtTokenHandler.prototype.getSigningKeys = function(cb) {
 return this._keyResolver.getSigningKeys(cb);
}

JwtTokenHandler.prototype.verifyToken = function(token, options, cb) {

  if (typeof options === 'function') {
    cb = options;
    options = {};
  }
  options = options || {};

  const self = this;
  const realm = options.realm || this._realm;
  const issuer = options.issuer || this._issuer;
  const audience = options.audience || this._audience;
  const scopeClaimName = options.scopeClaimName || this._scopeClaimName;
  const decodedJwt = Jwt.decode(token, {complete: true});

  if (!_.isObject(decodedJwt)) {
    return cb(new BearerTokenError({
      realm: realm,
      errorCode: 'invalid_token',
      description: 'The token is not a valid JSON Web Token (JWT)',
      uri: 'https://tools.ietf.org/html/rfc7519'
    }));
  }

  logger('Verifying JWT bearer token => %j', decodedJwt);

  if (!_.isObject(decodedJwt.header) || !_.isString(decodedJwt.header.kid)) {
    return cb(new BearerTokenError({
      realm: realm,
      errorCode: 'invalid_token',
      description: 'The token must specify a "kid" (Key ID) header parameter',
      uri: 'https://tools.ietf.org/html/rfc7519'
    }));
  }

  self._keyResolver.getSigningKey(decodedJwt.header.kid, function(err, key) {
    if (err) {
      logger('Unable to resolve key for kid=%s due to error %s', decodedJwt.header.kid, err.message);
      return cb(new BearerTokenError({
        realm: realm,
        errorCode: 'invalid_token',
        description: 'Unable to resolve key for token signature'
      }));
    }
    Jwt.verify(token,
      key.publicKey || key.rsaPublicKey,
      { algorithms: ['RS256', 'RS384', 'RS512'] },
      function(err, claims) {
        if (err) {
          logger('Unable to verify token due to error %s', err.message);
          if (err instanceof Jwt.TokenExpiredError) {
            return cb(new BearerTokenError({
              realm: realm,
              errorCode: 'invalid_token',
              description: 'The token is expired',
              uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.4'
            }));
          } else if (err instanceof Jwt.NotBeforeError) {
            return cb(new BearerTokenError({
              realm: realm,
              errorCode: 'invalid_token',
              description: 'The token is valid in the future',
              uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.5'
            }));
          } else {
            return cb(new BearerTokenError({
              realm: realm,
              errorCode: 'invalid_token',
              description: 'The token is not valid',
              uri: 'https://tools.ietf.org/html/rfc7519'
            }));
          }
        }

        if (claims.iss !== issuer) {
          logger('Token has invalid issuer (token=%s expected=%s)', claims.iss, issuer);
          return cb(new BearerTokenError({
            realm: realm,
            errorCode: 'invalid_token',
            description: 'The token issuer is not trusted',
            uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.1'
          }));
        }

        if (claims.aud !== audience) {
          logger('Token has invalid audience (token=%s expected=%s)', claims.aud, audience);
          return cb(new BearerTokenError({
            realm: realm,
            errorCode: 'invalid_token',
            description: 'The token is not valid for this audience',
            uri: 'https://tools.ietf.org/html/rfc7519#section-4.1.3'
          }));
        }

        if (_.isArray(options.scopes) || _.isString(options.scopes)) {
          const requiredScopes = _.isArray(options.scopes) ? options.scopes : [options.scopes];
          const grantedScopes = _.intersectionBy(claims[scopeClaimName], requiredScopes);
          if (requiredScopes.length !== grantedScopes.length) {
            logger('Token does not have required scopes (token=%s expected=%s)',
              grantedScopes.join(' '), requiredScopes.join(' '));
            return cb(new BearerTokenError({
              realm: realm,
              errorCode: 'insufficient_scope',
              scopes: requiredScopes,
              description: 'Insufficient scope for this resource',
              uri: 'https://tools.ietf.org/html/rfc6750#section-3'
            }));
          }
        }

        logger('Token was successfully verified => %j', claims);
        return cb(null, claims);
    });
  });
}

JwtTokenHandler.prototype.verifyRequest = function(req, options, cb) {
  var bearerHeader = false;
  var token;

  if (typeof options === 'function') {
    cb = options;
    options = {};
  }
  options = options || {};

  const realm = options.realm || this._realm;

  if (req.headers && req.headers.authorization) {
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
        realm: realm,
        errorCode: 'invalid_request',
        description: 'Request must specify a valid scheme and token for authorization header',
        uri: 'https://tools.ietf.org/html/rfc6750#section-2.1'
      }));
    }
  }

  if (req.query && req.query.access_token) {
    if (token && bearerHeader) {
      return cb(new BearerTokenError({
        realm: realm,
        errorCode: 'invalid_request',
        description: 'Request cannot have token in both authorization header and query parameter',
        uri: 'https://tools.ietf.org/html/rfc6750#section-2.3'
      }));
    }
    token = req.query.access_token;
  }

  if (req.headers && req.headers['content-type'] === 'application/x-www-form-urlencoded' &&
    req.body && req.body.access_token && req.method !== 'GET') {

    if (token) {
      if (bearerHeader) {
        return cb(new BearerTokenError({
          realm: realm,
          errorCode: 'invalid_request',
          description: 'Request cannot have token in both authorization header and post parameter',
          uri: 'https://tools.ietf.org/html/rfc6750#section-2.2'
        }));
      } else {
        return cb(new BearerTokenError({
          realm: realm,
          errorCode: 'invalid_request',
          description: 'Request cannot have token in both query and post parameter',
          uri: 'https://tools.ietf.org/html/rfc6750#section-2.2'
        }));
      }
    }
    token = req.body.access_token;
  }

  if (!token) {
    return cb(new BearerTokenError({
      realm: realm,
      errorCode: 'invalid_request',
      description: 'Request must specify a token in either an authorization header, query parameter, or post parameter',
      uri: 'https://tools.ietf.org/html/rfc6750'
    }));
  }

  return this.verifyToken(token, options, cb);
};

module.exports = JwtTokenHandler;
