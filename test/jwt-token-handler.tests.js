const _ = require('lodash');
const chai = require('chai');
const assert = chai.assert;
const expect = chai.expect;
const sinon = require('sinon');
const nock = require('nock');
const path = require('path');
const fs = require('fs');
const JwtTokenHandler = require('../lib/jwt-token-handler');

describe('JwtTokenHandler', function() {
  const baseUrl = 'http://authorization-server';
  const jwksPath = '/oauth2/v1/keys';
  const tokens = {
    id_token: {
      jwt: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkM0TmdMMlFIVHpvRVJfbzEzTGJza2pYWk1RV1FoUVRZZzNvdFBHR1pHWFkifQ.eyJzdWIiOiIwMHU1aXZzdnI1MzFVNWRoajBoNyIsIm5hbWUiOiJLYXJsIE1jR3Vpbm5lc3MiLCJsb2NhbGUiOiJlbi1VUyIsImVtYWlsIjoia21jZ3Vpbm5lc3NAb2t0YS5jb20iLCJ2ZXIiOjEsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5va3RhcHJldmlldy5jb20iLCJhdWQiOiJBTlJaaHlEaDhIQkZONWFiTjZSZyIsImlhdCI6MTQ2MDMxMzUxMiwiZXhwIjoxNDYwMzE3MTEyLCJqdGkiOiJGekFqdS14RVhaa2ZWSTJudmstdiIsImFtciI6WyJwd2QiXSwiaWRwIjoiMDBvNWl2c3ZxbEpTSlZCbWUwaDciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJrbWNndWlubmVzc0Bva3RhLmNvbSIsImdpdmVuX25hbWUiOiJLYXJsIiwiZmFtaWx5X25hbWUiOiJNY0d1aW5uZXNzIiwiem9uZWluZm8iOiJBbWVyaWNhL0xvc19BbmdlbGVzIiwidXBkYXRlZF9hdCI6MTQ1NzgzNDk1MiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF1dGhfdGltZSI6MTQ2MDMxMzUxMn0.cxx2NHLcN8-Fabbw3GfcfQYJut0s6dvhPBokvL2eZlXEz1PlC6uronOT55E8qLf4PgQbuSqiW9HQHtp6ollRGJzPGzjEvociHh9LnHmK8p2EUBS_JcddXuH2UxYbCFo45lp-wMhHUEQGaQaMzuNscIju2Xy93Dv9rCsl826hE1vNZAoiYpvLBlGF2rUE_w4RmZSIzbDYBe5ueBtTzM1KaLgIXExNXqHhsyHv2MZV5Mz0UUcg66P2HwEgDWoHHZQhx11u57-3Bd_S1PxIcM-EAtMhnj0onr588muaACgeVAh8P3-kK3MvzqhHBIMQCwUbmDO4b5DYcj3xaYVHq62Raw',
      issuer:'https://example.oktapreview.com',
      kid: 'C4NgL2QHTzoER_o13LbskjXZMQWQhQTYg3otPGGZGXY',
      expiresAt: 1460313512,
      audience: 'ANRZhyDh8HBFN5abN6Rg',
      subject: '00u5ivsvr531U5dhj0h7',
      email: 'kmcguinness@okta.com',
      jwks: baseUrl + jwksPath
    },
    access_token: {
      jwt: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjdFd0I2elR3NFYxSHRzVFRpZFlvcVpJNEZoeHJMM3M2Y283NmpuTFBKLWsifQ.eyJ2ZXIiOjEsImp0aSI6IkFULk1ydXZ0OHVUT1R2dThrMi11LTZaZDJsb3kyNG9PZkJuWFhEalhlQW5nV2ciLCJpc3MiOiJodHRwczovL2V4YW1wbGUub2t0YXByZXZpZXcuY29tL2FzL29yc0tNUXNTV1F2enlQWGJ6ME5ZIiwiYXVkIjoiQU5SWmh5RGg4SEJGTjVhYk42UmciLCJzdWIiOiIwMHU1aXZzdnI1MzFVNWRoajBoNyIsImlhdCI6MTQ2ODk0NTgzNCwiZXhwIjoxNDY4OTQ5NDM0LCJjaWQiOiJBTlJaaHlEaDhIQkZONWFiTjZSZyIsInVpZCI6IjAwdTVpdnN2cjUzMVU1ZGhqMGg3Iiwic2NwIjpbIm9wZW5pZCIsImVtYWlsIiwicHJvZmlsZSIsImFkZHJlc3MiLCJwaG9uZSJdLCJzdWJBbHROYW1lIjoia21jZ3Vpbm5lc3NAb2t0YS5jb20ifQ.f6RMEjYhjIMnxJr1xgJWBz_igYdN3hxxDPSOODUsJxD_Ud_w5tKVVLIAKIM70hZ1DFLytaIoRI71EvuKB3uUMh5AR0N_gvLZnamKdrKl9r5RD1WLbUL7sKm378b4KWW2n1gqZBXAn9Se_mdk1j0_6Dq63sc6qhjSn40VEINU6RV7uwP4OGo0RdFaVWGo14biMrxgGa38rlZc_k-p0fd8zL6nw4W5myrikqW-mF2Xf55B05Fec2GelBcqoyarnF5EiMU-6G4tO1TQC5LM8J0glqhRAkXBOjpAK8eTAKWYpIQY_7MuIt5VCvVQ9anBGJ2GMQWm_oy9thZaeItAhxthPw',
      issuer: 'https://example.oktapreview.com/as/orsKMQsSWQvzyPXbz0NY',
      kid: '7EwB6zTw4V1HtsTTidYoqZI4FhxrL3s6co76jnLPJ-k',
      expiresAt: 1468949434,
      audience: 'ANRZhyDh8HBFN5abN6Rg',
      subject: '00u5ivsvr531U5dhj0h7',
      email: 'kmcguinness@okta.com',
      jwks: fs.readFileSync(path.join(__dirname, 'keys.json'), 'utf8')
    }
  };

  describe('#JwtTokenHandler()', function() {
    const issuer = 'https://example.oktapreview.com';
    const audience = 'urn:example:audience';
    var handler;

    beforeEach(function() {
      nock.cleanAll();
      nock(baseUrl)
        .get(jwksPath)
        .replyWithFile(200, path.join(__dirname, 'keys.json'));
    });

    it('should require jwks or jwksUrl option', function() {
      var err;
      try {
        handler = new JwtTokenHandler({
          issuer: issuer,
          audience: audience
        });
      } catch (err) {
        err = err;
      }
      expect(err).not.to.be.null;
    });

    it('should require a jwks with valid RSA signature key', function() {
      var err;
      try {
        handler = new JwtTokenHandler({
          issuer: issuer,
          audience: audience,
          jwks: fs.readFileSync(path.join(__dirname, 'invalid-keys.json'), 'utf8')
        });
      } catch (err) {
        err = err;
      }
      expect(err).not.to.be.null;
    });

    it('should require a valid jwks', function() {
      var err;
      try {
        handler = new JwtTokenHandler({
          issuer: issuer,
          audience: audience,
          jwks: { "keys": null }
        });
      } catch (err) {
        err = err;
      }
      expect(err).not.to.be.null;
    });

    it('should require at least one jwk', function() {
      var err;
      try {
        handler = new JwtTokenHandler({
          issuer: issuer,
          audience: audience,
          jwks: { "keys": [] }
        });
      } catch (err) {
        err = err;
      }
      expect(err).not.to.be.null;
    });

    Object.keys(tokens).forEach(function(tokenType) {

      describe(tokenType, function() {

        const token = tokens[tokenType];

        beforeEach(function() {
          handler = new JwtTokenHandler({
            issuer: token.issuer,
            audience: token.audience,
            jwks: token.jwks
          });
        });

        it('should require issuer option', function() {
          var err;
          try {
            handler = new JwtTokenHandler({
              audience: token.audience,
              jwks: token.jwks
            });
          } catch (err) {
            err = err;
          }
          expect(err).not.to.be.null;
        });

        it('should require audience option', function() {
          var err;
          try {
            handler = new JwtTokenHandler({
              issuer: token.issuer,
              jwks: token.jwks
            });
          } catch (err) {
            err = err;
          }
          expect(err).not.to.be.null;
        });

        it('should have issuer property as option vaue', function() {
          expect(handler.issuer).to.be.equal(token.issuer);
        });

        it('should have audience property as option value', function() {
          expect(handler.audience).to.be.equal(token.audience);
        });

        it('should have realm property as default value', function() {
          expect(handler.realm).to.be.equal(token.audience);
        });

        it('should have realm property as option value', function() {
          handler = new JwtTokenHandler({
            issuer: token.issuer,
            audience: token.audience,
            realm: 'TEST',
            jwks: token.jwks
          });
          expect(handler.realm).to.be.equal('TEST');
        });

        it('should have requiredScopes property as option value', function() {
          handler = new JwtTokenHandler({
            issuer: token.issuer,
            audience: token.audience,
            scopes: ['test:scope'],
            jwks: token.jwks
          });
          expect(handler.requiredScopes).to.deep.equal(['test:scope']);
        });

        it('should have scopeClaimName property as option value', function() {
          handler = new JwtTokenHandler({
            issuer: token.issuer,
            audience: token.audience,
            scopeClaimName: 'test',
            jwks: token.jwks
          });
          expect(handler.scopeClaimName).to.be.equal('test');
        });

        it('should have scopeClaimName property as default value', function() {
          expect(handler.scopeClaimName).to.be.equal('scp');
        });

        it('should have jwks property with keys', function(done) {
          handler.getSigningKeys(function(err, keys) {
            expect(err).to.be.null;
            expect(keys).to.be.a('array');
            expect(keys.length).to.be.equal(2);
            expect(keys[0].rsaPublicKey).to.not.be.null;
            expect(keys[1].rsaPublicKey).to.not.be.null;
            done();
          })
        });
      });
    });
  });

  describe('#verifyRequest()', function() {

    Object.keys(tokens).forEach(function(tokenType) {

      describe(tokenType, function() {

        const token = tokens[tokenType];
        var clock;
        var handler;

        beforeEach(function() {
          clock = sinon.useFakeTimers((token.expiresAt - 60) * 1000);
          nock.cleanAll();
          nock(baseUrl)
            .get(jwksPath)
            .replyWithFile(200, path.join(__dirname, 'keys.json'));
          handler = new JwtTokenHandler({
            issuer: token.issuer,
            audience: token.audience,
            realm: 'TEST',
            jwks: token.jwks
          });
        });

        afterEach(function () {
          try { clock.restore(); } catch (e) {}
        });

        describe('with valid token sent via authorization header', function() {

          it('should have subject, issuer, and audience claims', function(done) {
            handler.verifyRequest({
              headers: {
                authorization: 'BEARER ' + token.jwt
              }
            }, function(err, claims) {
              expect(err).to.be.null;
              expect(claims.sub).to.equal(token.subject);
              expect(claims.iss).to.equal(token.issuer);
              expect(claims.aud).to.equal(token.audience);
              done();
            });
          });

        });

        describe('with valid token sent via query parameter', function() {

          it('should have subject, issuer, and audience claims', function(done) {
            handler.verifyRequest({
              query: {
                access_token: token.jwt
              }
            }, function(err, claims) {
              expect(err).to.be.null;
              expect(claims.sub).to.equal(token.subject);
              expect(claims.iss).to.equal(token.issuer);
              expect(claims.aud).to.equal(token.audience);
              done()
            })
          });

        });

        describe('with valid token sent via body parameter', function() {

          it('should have subject, issuer, and audience claims', function(done) {
            handler.verifyRequest({
              headers: {
                'content-type': 'application/x-www-form-urlencoded'
              },
              body: {
                access_token: token.jwt
              }
            }, function(err, claims) {
              expect(err).to.be.null;
              expect(claims.sub).to.equal(token.subject);
              expect(claims.iss).to.equal(token.issuer);
              expect(claims.aud).to.equal(token.audience);
              done();
            })
          });

        });

        describe('missing tokens', function() {

          it('should have invalid_request error', function(done) {
            handler.verifyRequest({}, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_request');
              expect(err.statusCode).to.equal(400)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_request", ' +
                'error_description="Request must specify a token in either an authorization header, query parameter, or post parameter", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750"');
              expect(claims).to.be.undefined;
              done();
            })
          });

          it('should use audience as realm for challenge', function(done) {
            handler = new JwtTokenHandler({
              issuer: token.issuer,
              audience: token.audience,
              jwks: token.jwks
            });
            handler.verifyRequest({}, function(err, claims) {
                expect(err).not.to.be.null;
                expect(err.errorCode).to.equal('invalid_request');
                expect(err.statusCode).to.equal(400)
                expect(err.challenge).to.equal('Bearer realm="' + token.audience + '", error="invalid_request", ' +
                  'error_description="Request must specify a token in either an authorization header, query parameter, or post parameter", ' +
                  'error_uri="https://tools.ietf.org/html/rfc6750"');
                expect(claims).to.be.undefined;
                done();
            });
          });

        });

        describe('with body with missing content-type', function() {

          it('should have invalid_request error', function(done) {
            handler.verifyRequest({
              body: {
                access_token: token.jwt
              }
            }, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_request');
              expect(err.statusCode).to.equal(400)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_request", ' +
                'error_description="Request must specify a token in either an authorization header, query parameter, or post parameter", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750"');
              expect(claims).to.be.undefined;
              done();
            })
          });

        });

        describe('with body and query params', function() {

          it('should have invalid_request error', function(done) {
            handler.verifyRequest({
              headers: {
                'content-type': 'application/x-www-form-urlencoded'
              },
              body: {
                access_token: token.jwt
              },
              query: {
                access_token: token.jwt
              }
            }, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_request');
              expect(err.statusCode).to.equal(400)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_request", ' +
                'error_description="Request cannot have token in both query and post parameter", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750#section-2.2"');
              expect(claims).to.be.undefined;
              done();
            })
          });

        });

        describe('with query and authorization params', function() {

          it('should have invalid_request error', function(done) {
            handler.verifyRequest({
              headers: {
                authorization: 'BEARER' + token.jwt
              },
              query: {
                access_token: token.jwt
              }
            }, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_request');
              expect(err.statusCode).to.equal(400)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_request", ' +
                'error_description="Request must specify a valid scheme and token for authorization header", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750#section-2.1"');
              expect(claims).to.be.undefined;
              done();
            })
          });

        });

        describe('with body and authorization params', function() {

          it('should have invalid_request error', function(done) {
            handler.verifyRequest({
              headers: {
                authorization: 'BEARER' + token.jwt
              },
              body: {
                access_token: token.jwt
              }
            }, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_request');
              expect(err.statusCode).to.equal(400)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_request", ' +
                'error_description="Request must specify a valid scheme and token for authorization header", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750#section-2.1"');
              expect(claims).to.be.undefined;
              done();
            })
          });

        });

        describe('with invalid authorization scheme', function() {

          it('should have invalid_request error', function(done) {
            handler.verifyRequest({
              headers: {
                authorization: 'OAUTH2' + token.jwt
              }
            }, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_request');
              expect(err.statusCode).to.equal(400)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_request", ' +
                'error_description="Request must specify a valid scheme and token for authorization header", ' +
                'error_uri="https://tools.ietf.org/html/rfc6750#section-2.1"');
              expect(claims).to.be.undefined;
              done();
            })
          });

        });

      });

    });

  });

  describe('#verifyToken()', function() {

    describe('id_token', function() {

      describe('with missing signature keys', function() {

        it('should not resolve a signing key', function(done) {

          handler = new JwtTokenHandler({
            issuer: tokens.id_token.issuer,
            audience: tokens.id_token.audience,
            realm: 'TEST',
            jwks: fs.readFileSync(path.join(__dirname, 'refresh-keys.json'), 'utf8')
          });

          handler.verifyToken(tokens.id_token.jwt, function(err, claims) {
            expect(err).not.to.be.null;
            expect(err.errorCode).to.equal('invalid_token');
            expect(err.statusCode).to.equal(401)
            expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
              'error_description="Unable to resolve key for token signature"');
            expect(claims).to.be.undefined;
            done();
          })
        });

      });

      describe('with invalid signature keys', function() {

        it('should reject token signature', function(done) {

          handler = new JwtTokenHandler({
            issuer: tokens.id_token.issuer,
            audience: tokens.id_token.audience,
            realm: 'TEST',
            jwks: fs.readFileSync(path.join(__dirname, 'invalid-signature-keys.json'), 'utf8')
          });

          nock.cleanAll();
          nock(baseUrl)
            .get(jwksPath)
            .replyWithFile(200, path.join(__dirname, 'invalid-signature-keys.json'));

          handler.verifyToken(tokens.id_token.jwt, function(err, claims) {
            expect(err).not.to.be.null;
            expect(err.errorCode).to.equal('invalid_token');
            expect(err.statusCode).to.equal(401)
            expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
              'error_description="The token is not valid", error_uri="https://tools.ietf.org/html/rfc7519"');
            expect(claims).to.be.undefined;
            done();
          })
        });

      });

    });


    describe('access_token', function() {

      const token = tokens.access_token;
      var clock;
      var handler;

      beforeEach(function() {
        clock = sinon.useFakeTimers((token.expiresAt - 60) * 1000);
        nock.cleanAll();
        nock(baseUrl)
          .get(jwksPath)
          .replyWithFile(200, path.join(__dirname, 'keys.json'));

        handler = new JwtTokenHandler({
          issuer: token.issuer,
          audience: token.audience,
          realm: 'TEST',
          jwks: token.jwks
        });
      });

      afterEach(function () {
        clock.restore();
      });

      describe('with missing signature keys', function() {

        it('should not resolve a signing key', function(done) {

          handler = new JwtTokenHandler({
            issuer: tokens.access_token.issuer,
            audience: tokens.access_token.audience,
            realm: 'TEST',
            jwks: baseUrl + jwksPath
          });

          nock.cleanAll();
          nock(baseUrl)
            .get(jwksPath)
            .replyWithFile(200, path.join(__dirname, 'refresh-keys.json'));

          handler.verifyToken(tokens.access_token.jwt, function(err, claims) {
            expect(err).not.to.be.null;
            expect(err.errorCode).to.equal('invalid_token');
            expect(err.statusCode).to.equal(401)
            expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
              'error_description="Unable to resolve key for token signature"');
            expect(claims).to.be.undefined;
            done();
          })
        });

      });

      describe('with invalid signature keys', function() {

        it('should reject token signature', function(done) {

          handler = new JwtTokenHandler({
            issuer: tokens.access_token.issuer,
            audience: tokens.access_token.audience,
            realm: 'TEST',
            jwks: baseUrl + jwksPath
          });

          nock.cleanAll();
          nock(baseUrl)
            .get(jwksPath)
            .replyWithFile(200, path.join(__dirname, 'invalid-signature-keys.json'));

          handler.verifyToken(tokens.access_token.jwt, function(err, claims) {
            expect(err).not.to.be.null;
            expect(err.errorCode).to.equal('invalid_token');
            expect(err.statusCode).to.equal(401)
            expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
              'error_description="The token is not valid", error_uri="https://tools.ietf.org/html/rfc7519"');
            expect(claims).to.be.undefined;
            done();
          })
        });

      });

      describe('with valid scoped token', function() {

        it('should have single scope', function(done) {
          handler.verifyToken(token.jwt, { issuer: token.issuer, audience: token.audience, scopes: ['email'] } ,
            function(err, claims) {
              expect(err).to.be.null;
              expect(claims.sub).to.equal(token.subject);
              expect(claims.iss).to.equal(token.issuer);
              expect(claims.aud).to.equal(token.audience);
              expect(claims.hasScopes('email')).to.be.true;
              expect(claims.hasScopes(['email'])).to.be.true;
              expect(claims.hasScopes('missing')).to.be.false;
              expect(claims.hasScopes(['missing'])).to.be.false;
              done();
            })
        });

        it('should have multiple scopes', function(done) {
          handler.verifyToken(token.jwt, { issuer: token.issuer, audience: token.audience, scopes: ['email', 'phone'] },
            function(err, claims) {
              expect(err).to.be.null;
              expect(claims.sub).to.equal(token.subject);
              expect(claims.iss).to.equal(token.issuer);
              expect(claims.aud).to.equal(token.audience);
              expect(claims.hasScopes(['email', 'phone'])).to.be.true;
              expect(claims.hasScopes(['email', 'phone', 'missing'])).to.be.false;
              done();
            })
        });

      });
    });

    /*
      Tests should be valid for both id_token and access_token
     */
    Object.keys(tokens).forEach(function(tokenType) {

      describe(tokenType, function() {

        const token = tokens[tokenType];
        var clock;
        var handler;

        beforeEach(function() {
          clock = sinon.useFakeTimers((token.expiresAt - 60) * 1000);
          nock.cleanAll();
          nock(baseUrl)
            .get(jwksPath)
            .replyWithFile(200, path.join(__dirname, 'keys.json'));

          handler = new JwtTokenHandler({
            issuer: token.issuer,
            audience: token.audience,
            realm: 'TEST',
            jwks: token.jwks
          });
        });

        afterEach(function () {
          clock.restore();
        });

        describe('with valid token', function() {

          it('should have subject, issuer, and audience claims', function(done) {
            handler.verifyToken(token.jwt, function(err, claims) {
              expect(err).to.be.null;
              expect(claims.sub).to.equal(token.subject);
              expect(claims.iss).to.equal(token.issuer);
              expect(claims.aud).to.equal(token.audience);
              done();
            });
          });

        });

        describe('with valid token and options', function() {

          handler = new JwtTokenHandler({
            issuer: 'https://example.com/invalid/issuer',
            audience: 'urn:invalid:audience',
            realm: 'TEST',
            jwks: token.jwks
          });

          it('should have subject, issuer, and audience claims', function(done) {
            handler.verifyToken(token.jwt, { issuer: token.issuer, audience: token.audience }, function(err, claims) {
              expect(err).to.be.null;
              expect(claims.sub).to.equal(token.subject);
              expect(claims.iss).to.equal(token.issuer);
              expect(claims.aud).to.equal(token.audience);
              done();
            });
          });

          it('should return insufficient_scope error for single scope', function(done) {
            handler.verifyToken(token.jwt, { scopes: ['missing'] },
              function(err, claims) {
                expect(err).not.to.be.null;
                expect(err.errorCode).to.equal('insufficient_scope');
                expect(err.statusCode).to.equal(403)
                expect(err.challenge).to.equal('Bearer realm="TEST", error="insufficient_scope", ' +
                  'error_description="Insufficient scope for this resource", ' +
                  'error_uri="https://tools.ietf.org/html/rfc6750#section-3", scope="missing"');
                expect(err.uri).to.equal('https://tools.ietf.org/html/rfc6750#section-3');
                expect(claims).to.be.undefined;
                done();
              })
          });

          it('should return insufficient_scope error for multiple scopes', function(done) {
            handler.verifyToken(token.jwt, { scopes: ['missing', 'email', 'foo'] },
              function(err, claims) {
                expect(err).not.to.be.null;
                expect(err.errorCode).to.equal('insufficient_scope');
                expect(err.statusCode).to.equal(403)
                expect(err.challenge).to.equal('Bearer realm="TEST", error="insufficient_scope", ' +
                  'error_description="Insufficient scope for this resource", ' +
                  'error_uri="https://tools.ietf.org/html/rfc6750#section-3", scope="missing email foo"');
                expect(err.uri).to.equal('https://tools.ietf.org/html/rfc6750#section-3');
                expect(claims).to.be.undefined;
                done();
              })
          });
        });

        describe('with invalid token', function() {

          it('should use audience as realm for challenge', function(done) {
            handler = new JwtTokenHandler({
              issuer: 'https://example.com/invalid/issuer',
              audience: token.audience,
              jwks: token.jwks
            });
            handler.verifyToken(token.jwt, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_token');
              expect(err.statusCode).to.equal(401)
              expect(err.challenge).to.equal('Bearer realm="' + token.audience + '", error="invalid_token", ' +
                'error_description="The token issuer is not trusted", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.1"');
              expect(err.uri).to.equal('https://tools.ietf.org/html/rfc7519#section-4.1.1');
              expect(claims).to.be.undefined;
              done();
            });
          });

          it('should be expired', function(done) {
            clock.restore()
            handler.verifyToken(token.jwt, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_token');
              expect(err.statusCode).to.equal(401)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
                'error_description="The token is expired", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.4"');
              expect(err.uri).to.equal('https://tools.ietf.org/html/rfc7519#section-4.1.4');
              expect(claims).to.be.undefined;
              done();
            })
          });

          it('should not have valid issuer', function(done) {
            handler = new JwtTokenHandler({
              issuer: 'https://example.com/invalid/issuer',
              audience: token.audience,
              realm: 'TEST',
              jwks: token.jwks
            });

            handler.verifyToken(token.jwt, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_token');
              expect(err.statusCode).to.equal(401)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
                'error_description="The token issuer is not trusted", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.1"');
              expect(err.uri).to.equal('https://tools.ietf.org/html/rfc7519#section-4.1.1');
              expect(claims).to.be.undefined;
              done();
            })
          });

          it('should not have valid audience', function(done) {
            handler = new JwtTokenHandler({
              issuer: token.issuer,
              audience: 'urn:invalid:audience',
              realm: 'TEST',
              jwks: token.jwks
            });

            handler.verifyToken(token.jwt, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_token');
              expect(err.statusCode).to.equal(401)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
                'error_description="The token is not valid for this audience", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.3"');
              expect(err.uri).to.equal('https://tools.ietf.org/html/rfc7519#section-4.1.3');
              expect(claims).to.be.undefined;
              done();
            })
          });
        });


        describe('with invalid token and override options', function() {

          it('should not have valid issuer', function(done) {
            handler.verifyToken(token.jwt, { issuer: 'https://example.com/invalid/issuer' },
              function(err, claims) {
                expect(err).not.to.be.null;
                expect(err.errorCode).to.equal('invalid_token');
                expect(err.statusCode).to.equal(401)
                expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
                  'error_description="The token issuer is not trusted", ' +
                  'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.1"');
                expect(err.uri).to.equal('https://tools.ietf.org/html/rfc7519#section-4.1.1');
                expect(claims).to.be.undefined;
                done();
              })
          });

          it('should not have valid audience', function(done) {
            handler.verifyToken(token.jwt, { audience: 'urn:invalid:audience' }, function(err, claims) {
              expect(err).not.to.be.null;
              expect(err.errorCode).to.equal('invalid_token');
              expect(err.statusCode).to.equal(401)
              expect(err.challenge).to.equal('Bearer realm="TEST", error="invalid_token", ' +
                'error_description="The token is not valid for this audience", ' +
                'error_uri="https://tools.ietf.org/html/rfc7519#section-4.1.3"');
              expect(err.uri).to.equal('https://tools.ietf.org/html/rfc7519#section-4.1.3');
              expect(claims).to.be.undefined;
              done();
            })
          });

        });

      });

    });
  });
});
