'use strict';

const JwksClient = require('jwks-rsa');
const CertUtil = require('./cert-util');
const url = require('url');
const _ = require('lodash');
const logger = require('debug')('oauth2-jwt-bearer');

module.exports = function(jwks, options) {
  if (_.isString(jwks)) {
    const jwksUrl = url.parse(jwks);
    if (jwksUrl.protocol && jwksUrl.host) {
      return JwksClient(_.extend({}, options, { jwksUri: jwks }));
    } else {
      jwks = JSON.parse(jwks);
    }
  } else {
    jwks = _.clone(jwks);
  }

  if (!jwks.keys) {
    throw new TypeError('jwks must be a valid JSON Web Key Set (JWKS)');
  }

  jwks.keys = _.chain(jwks.keys).filter(function(key) {
    return key.use === 'sig' && key.kty === 'RSA' && key.kid && (key.x5c && key.x5c.length || key.n && key.e);
  }).map(function (key) {
    if (key.x5c && key.x5c.length) {
      return { kid: key.kid, nbf: key.nbf, publicKey: CertUtil.certToPEM(key.x5c[0]) };
    } else {
      return { kid: key.kid, nbf: key.nbf, rsaPublicKey: CertUtil.rsaPublicKeyToPEM(key.n, key.e) };
    }
  }).value();

  if (jwks.keys.length < 1) {
    throw new TypeError('jwks must be a valid JSON Web Key Set (JWKS) with at least one RSA signature key');
  }

  return {
    getKeys: function(kid, cb) {
      return cb(null, jwks.keys);
    },
    getSigningKeys: function(kid, cb) {
      return cb(null, jwks.keys);
    },
    getSigningKey: function(kid, cb) {
      logger("Fetching signing key for '%s'", kid);
      const key = _.find(jwks, function(key) {
        return (key.kid === kid);
      });
      if (key) {
        return cb(null, key);
      } else {
        logger("Unable to find a signing key that matches '%s'", kid);
        return cb(new JwksClient.SigningKeyNotFoundError(
          "Unable to find a signing key that matches '" + kid + "'"
          ));
      }
    }
  };
}







