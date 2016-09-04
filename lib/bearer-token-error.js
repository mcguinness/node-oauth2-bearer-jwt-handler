'use strict';

var BearerTokenError = function(params) {
  var challenge = 'Bearer ';
  if (params.realm) {
    challenge += 'realm="' + params.realm + '"';
  }
  if (params.scopes) {
    challenge += ', scope="' + params.scopes.join(' ') + '"';
  }
  if (params.errorCode) {
    challenge += ', error="' + params.errorCode + '"';
  }
  if (params.description && params.description.length) {
    challenge += ', error_description="' + params.description + '"';
  }
  if (params.uri && params.uri.length) {
    challenge += ', error_uri="' + params.uri + '"';
  }

  Error.call(this, params.description || params.errorCode);
  Error.captureStackTrace(this, this.constructor);

  this.name = 'BearerTokenError';
  this.message = params.description || params.errorCode;
  this.challenge = challenge;
  if (params.errorCode) {
    this.errorCode = params.errorCode;
  }
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
  if (params.uri) {
    this.uri = params.uri;
  }
};

BearerTokenError.prototype = Object.create(Error.prototype);
BearerTokenError.prototype.constructor = BearerTokenError;

module.exports = BearerTokenError;
