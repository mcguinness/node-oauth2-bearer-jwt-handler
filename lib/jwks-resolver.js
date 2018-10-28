'use strict';

const jwksClientFactory = require('jwks-rsa');
const SigningKeyNotFoundError = require('jwks-rsa').SigningKeyNotFoundError;
const CertUtil = require('./cert-util');
const url = require('url');
const _ = require('lodash');
const logger = require('debug')('oauth2-jwt-bearer');

class StaticJwksResolver {
  constructor(jwks) {
    if (!jwks) {
      throw new Error('jwks is a required argument');
    }
    if (_.isString(jwks)) {
      jwks = JSON.parse(jwks);
    } else {
      // clone to mutate
      jwks = _.clone(jwks);
    }

    if (!jwks.keys) {
      throw new Error('jwks must be a valid JSON Web Key Set (JWKS)');
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
      throw new Error('jwks must be a valid JSON Web Key Set (JWKS) with at least one RSA signature key');
    }

    this._jwks = jwks;
  }

  getKeys() {
    return Promise.resolve(this._jwks.keys);
  }

  getSigningKeys() {
    return Promise.resolve(this._jwks.keys);
  }

  getSigningKey(kid) {
    logger("Fetching signing key for '%s'", kid);
    const key = this._jwks.keys.find(key => {
      return (key.kid === kid);
    });
    if (key) {
      return Promise.resolve(key);
    } else {
      logger("Unable to find a signing key that matches '%s'", kid);
      return Promise.reject(new SigningKeyNotFoundError(
        `Unable to find a signing key that matches ${kid}`
      ));
    }
  }
}

class DynamicJwksResolver {
  constructor(options) {
    this._jwksClient = jwksClientFactory(options);
  }

  getKeys() {
    const client = this._jwksClient;
    return new Promise((resolve, reject) => {
      client.getKeys((err, keys) => {
        if (err) {
          return reject(err);
        }
        return resolve(keys);
      })
    });
  }

  getSigningKeys() {
    const client = this._jwksClient;
    return new Promise((resolve, reject) => {
      client.getKeys((err, keys) => {
        if (err) {
          return reject(err);
        }
        return resolve(keys);
      })
    });
  }

  getSigningKey(kid) {
    const client = this._jwksClient;
    return new Promise((resolve, reject) => {
      client.getSigningKey(kid, (err, key) => {
        if (err) {
          return reject(err);
        }
        return resolve(key);
      })
    });
  }
}

class JwksResolver {

  constructor(jwks, options) {
    options = _.clone(options);
    this._resolvers = [];

    if (_.isString(jwks)) {
      const urlTest = url.parse(jwks);
      if (urlTest.protocol && urlTest.host) {
        this._resolvers.push(new DynamicJwksResolver(
          _.defaults(options, {
            jwksUri: jwks
          })
        ));
      } else {
        this._resolvers.push(new StaticJwksResolver(jwks));
        if (options.jwksUri) {
          this._resolvers.push(new DynamicJwksResolver(options));
        }
      }
    }
    else {
      if (_.isObject(jwks)) {
        this._resolvers.push(new StaticJwksResolver(jwks));
      }
      if (options.jwksUri) {
        this._resolvers.push(new DynamicJwksResolver(options));
      }
    }
    if (this._resolvers.length < 1) {
      throw new Error('At least one key resolver is required')
    }
  }

  getKeys() {
    const promises = [];
    this._resolvers.forEach(resolver => {
      promises.push(resolver.getKeys())
    })

    return new Promise((resolve, reject) => {
      Promise.all(promises)
        .then(values => {
          const keys = new Map();
          values.forEach(value => {
            value.forEach(key => {
              keys.set(key.kid, key);
            })
          })
          return resolve(Array.from(keys.values()));
        })
        .catch(reason => {
          return reject(reason);
        })
    });
  }

  getSigningKeys() {
    const promises = [];
    this._resolvers.forEach(resolver => {
      promises.push(resolver.getSigningKeys())
    })

    return new Promise((resolve, reject) => {
      Promise.all(promises)
        .then((values) => {
          const keys = new Map();
          values.forEach(value => {
            value.forEach(key => {
              keys.set(key.kid, key);
            })
          })
          return resolve(Array.from(keys.values()));
        })
        .catch(reason => {
          return reject(reason);
        })
    });
  }

  getSigningKey(kid) {
    const promises = [];
    this._resolvers.forEach(resolver => {
      promises.push(resolver.getSigningKey(kid))
    })

    return new Promise((resolve, reject) => {
      Promise.race(promises)
        .then(key => {
          return resolve(key)
        })
        .catch(reason => {
          return reject(reason);
        })
    });
  }
}


module.exports = JwksResolver;

