'use strict';

const BearerTokenError = require('./bearer-token-error');

var InvalidTokenError = function(description, realm, uri) {
  var params = {
    realm: realm,
    errorCode: 'invalid_token',
    description: description,
    uri: uri
  }

  BearerTokenError.call(this, params);
  Error.captureStackTrace(this, this.constructor);

  this.name = 'InvalidTokenError';
}

InvalidTokenError.prototype = Object.create(BearerTokenError.prototype);
InvalidTokenError.prototype.constructor = InvalidTokenError;

module.exports = InvalidTokenError;
