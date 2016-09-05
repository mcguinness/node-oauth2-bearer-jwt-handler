'use strict';

const paramKeys = ['realm', 'errorCode', 'description', 'uri', 'scopes'];

var BearerTokenError = function(params) {
  var challenge = 'Bearer ';
  var count = 0;
  params = params || {};

  paramKeys.forEach(function(key) {
    if (params[key] && params[key].length) {
      if (count++) {
        challenge += ', ';
      }
      switch (key) {
        case 'realm':
          challenge += 'realm="' + params.realm + '"';
          this.realm = params.realm;
          break;
        case 'errorCode':
          challenge += 'error="' + params.errorCode + '"';
          this.errorCode = params.errorCode;
          break
        case 'description':
          challenge += 'error_description="' + params.description + '"';
          break;
        case 'uri':
          challenge += 'error_uri="' + params.uri + '"';
          this.uri = params.uri;
          break;
        case 'scopes':
          challenge += 'scope="' + params.scopes.join(' ') + '"';
          this.scopes = params.scopes;
          break;
      }
    }
  }, this);

  Error.call(this, params.description || params.errorCode);
  Error.captureStackTrace(this, this.constructor);

  this.name = 'BearerTokenError';
  this.message = params.description || params.errorCode;
  this.challenge = challenge;

  if (params.statusCode) {
    this.statusCode = params.statusCode;
  } else {
    switch (params.errorCode) {
      case 'invalid_request':
        this.statusCode = 400;
        break;
      case 'invalid_token':
        this.statusCode = 401;
        break;
      case 'insufficient_scope':
        this.statusCode = 403;
        break;
      default:
        this.statusCode = 400;
        break;
    }
  }
};

BearerTokenError.prototype = Object.create(Error.prototype);
BearerTokenError.prototype.constructor = BearerTokenError;

module.exports = BearerTokenError;
