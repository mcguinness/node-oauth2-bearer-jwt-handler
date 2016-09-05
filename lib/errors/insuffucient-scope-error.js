'use strict';

const BearerTokenError = require('./bearer-token-error');

var InsufficientScopeError = function(description, scopes, realm, uri) {
  var params = {
    realm: realm,
    errorCode: 'insufficient_scope',
    description: description,
    uri: uri,
    scopes: scopes
  }

  BearerTokenError.call(this, params);
  Error.captureStackTrace(this, this.constructor);

  this.name = 'InsufficientScopeError';
}

InsufficientScopeError.prototype = Object.create(BearerTokenError.prototype);
InsufficientScopeError.prototype.constructor = InsufficientScopeError;

module.exports = InsufficientScopeError;
