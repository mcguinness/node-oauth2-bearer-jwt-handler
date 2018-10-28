# OAuth 2.0 Bearer JSON Web Token (JWT) Handler

A reusable token handler that validates a JWT access token according to [RFC 6750](https://tools.ietf.org/html/rfc6750) with an RSA [JWKS](https://tools.ietf.org/html/rfc7517) Key Provider.

The token handler implements [best current practices](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-03) for JSON Web Tokens.

The token handler isn't coupled to any API or Web framework but supports a generic parser for a HTTP request message.


## Usage

```js
const JwtTokenHandler = require('node-oauth2-bearer-jwt-handler').JwtTokenHandler;

```


declare function greet(greeting: string): void;
declare class MyClass {
    constructor(someParam?: string);

    someProperty: string[];

    myMethod(opts: MyClass.MyClassMethodOptions): number;
}


### Required Token Handler Options

Option | Description
------ | --------
`issuer`  | The required issuer of the JWT token.  The JWT token will fail to validate if the token issuer doesn't match this value. (See [Validate Issuer and Subject](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-03#section-3.8))
`audience` | The  required audience of the JWT token.  This is usually a value you define for your OAuth 2.0 Protected Resource Server (e.g. `https://api.example.com`).  The JWT token will fail to validate if the token audience doesn't match this value. (See [Use and Validate Audience](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-03#section-3.9))
`jwks`  | A JSON String, URL or Object of a JWKS used to validate the JWT signature

#### JWKS Resolver

The token handler supports using a static or dynamic JWKS resolver for JWT signing keys.

`jwks` | Resolver
------ | --------
JWKS JSON String or Object | Static Resolver
URL | Dynamic Resolver

The dynamic resolver uses the following default options:

```
{
  strictSsl: true,
  rateLimit: true,
  cache: true
}
```

The dynamic resolved is recommended as it supports key rollover.  If the resolver finds a new `kid` that wasn't published in the JWKS it will attempt to refresh the JWKS to see if the new `kid` was published.

> Note:  All JWT tokens must have a `kid` JOSE header specified for the resolver to locate the correct public key

##### Static  JWKS Example

```
// JWKS String
const handler = new JwtTokenHandler({
  issuer: process.env.ISSUER,
  audience: process.env.AUDIENCE,
  jwks: '{"keys":[{"alg":"RS256","e":"AQAB","n":"tcnyvuVCrsFEKCwHDenS3Ocjed8eWDv3zLtD2K_iZfE8BMj2wpTfn6Ry8zCYey3mWlKdxIybnV9amrujGRnE0ab6Q16v9D6RlFQLOG6dwqoRKuZy33Uyg8PGdEudZjGbWuKCqqXEp-UKALJHV-k4wWeVH8g5d1n3KyR2TVajVJpCrPhLFmq1Il4G_IUnPe4MvjXqB6CpKkog1-ThWsItPRJPAM-RweFHXq7KfChXsYE7Mmfuly8sDQlvBmQyxZnFHVuiPfCvGHJjpvHy11YlHdOjfgqHRvZbmo30-y0X_oY_yV4YEJ00LL6eJWU4wi7ViY3HP6_VCdRjHoRdr5L_Dw","kty":"RSA","use":"sig","kid":"C4NgL2QHTzoER_o13LbskjXZMQWQhQTYg3otPGGZGXY"}]}'
});
```

```
// JWKS File
const handler = new JwtTokenHandler({
  issuer: process.env.ISSUER,
  audience: process.env.AUDIENCE,
  jwks: fs.readFileSync(process.env.JWKS_PATH, 'utf8')
});
```

##### Dynamic JWKS Example

```
//JWKS as URL (supports key rollover)
const handler = new JwtTokenHandler({
  issuer: process.env.TOKEN_ISSUER,
  audience: process.env.TOKEN_AUDIENCE,
  jwks: process.env.JWKS_URL,
});
```

### Optional Token Handler Options

Option | Description
------ | --------
`realm`  | The "realm" attribute that indicates the scope of protection in the manner described in HTTP/1.1 [RFC2617](https://tools.ietf.org/html/rfc2617#section-1.2).  The default value is the same value as `audience`
`clockTolerance` | The number of seconds to tolerate when checking the `nbf` and `exp` claims of a JWT, useful to deal with small clock differences among different servers.  The default is 5 seconds.

## Token Validation

A JWT token can be validated using the `verifyToken` method with a callback.

```
handler.verifyToken(token, function(err, claims))
// optionally override token handler options
handler.verifyToken(token, options, function(err, claims))
```

### Examples

```
handler.verifyToken(token, options, function(err, claims) {
    if (err) {
        res.set('WWW-Authenticate', err.challenge)l
        res.status(err.statusCode).send(err.message)
        return;
    }
    // handle claims
    console.log(claims.iss);
    console.log(claims.aud);
    console.log(claims.sub);
})
```

### Scope Validation (Optional)

The token handler can optionally validate that a scope claim value is present in the token when validating the token. This is common JWT access token validation requirement for an OAuth 2.0 Protected Resource.  If the token doesn't contain the scopes specified, the verification callback will return an `InsufficientScopeError` error to challenge the caller for the required scopes.

Param Name | Description
---------- | -----------
`scopes`   | Array of scopes that must be present in the JWT token
`scopesClaimName` | The name of the claim in the JWT that contains granted scopes

#### Example

```
const handler = new JwtTokenHandler({
  issuer: process.env.TOKEN_ISSUER,
  audience: process.env.TOKEN_AUDIENCE,
  jwks: process.env.TOKEN_JWKS_URL,
  scopes: ['api:read', "api:write"],
  scopesClaimName: 'scopes'
});
```


## Request Validation

The `verifyRequest` method attempts to parse the HTTP request for a token using a method (`HEADER`, `QUERY`, or `FORM_BODY`) and validate the token using `verifyToken`.

The default handler options will attempt to first look for an access token in the `Authorization` header, if not token is found it will look for a token in the `access_token` query parameter, finally if the request has a `Content-Type: application/x-www-form-urlencoded' and the HTTP Method is not GET it will look for the form body parameter `access_token`.

Once a token if found, it is processed with the `verifyToken` method.

```
handler.verifyRequest(request, function(err, claims))
// optionally override token handler options
handler.verifyRequest(request, options, function(err, claims))
```


> You can determine what token methods `verifyRequest` uses with the `methods` options.  The default option is to use all methods `methods: ["HEADER", "QUERY", "FORM_BODY"]`


### Example

Most API and Web frameworks use a similar object model for a HTTP request.  You can usually just pass the raw request object to the `verifyRequest` method if it matches the following contract:

```
{
  headers: {
    key: value
  },
  query: {
    key: value
  },
  body: {
    key: value
  }
}
```

If your request doesn't match the contract, you will need to transform the request!


#### Authorization Header Example

```
handler.verifyRequest({
  headers: {
    authorization: token
  },
  {
    methods: [JwtTokenHandler.methods.HEADER]
  },
  function(err, claims) {
    if (err) {
        res.set('WWW-Authenticate', err.challenge)l
        res.status(err.statusCode).send(err.message)
        return;
    }
    // handle claims
    console.log(claims.iss);
    console.log(claims.aud);
    console.log(claims.sub);
  }
}
```

#### Query Paramer Example

```
handler.verifyRequest({
  query: {
    access_token: token
  },
  {
    methods: [JwtTokenHandler.methods.QUERY]
  },
  function(err, claims) {
    if (err) {
        res.set('WWW-Authenticate', err.challenge)l
        res.status(err.statusCode).send(err.message)
        return;
    }
    // handle claims
    console.log(claims.iss);
    console.log(claims.aud);
    console.log(claims.sub);
  }
}
```

#### Form Body Example

```
handler.verifyRequest({
  body: {
    access_token: token
  },
  {
    methods: [JwtTokenHandler.methods.FORM_BODY]
  },
  function(err, claims) {
    if (err) {
        res.set('WWW-Authenticate', err.challenge)l
        res.status(err.statusCode).send(err.message)
        return;
    }
    // handle claims
    console.log(claims.iss);
    console.log(claims.aud);
    console.log(claims.sub);
  }
}
```

### Errors

The package exports 3 error classes that provide a common interface to easily construct WWW-Authenticate responses in your API or Web framework with correct challenge and HTTP status code such as:

```
res.set('WWW-Authenticate', err.challenge)
res.status(err.statusCode).send(err.message)
```

The following typescript summarizes the interface:

```
enum BearerTokenErrorCode {
    invalid_request,
    invalid_token,
    insufficient_scope
}

interface BearerTokenErrorInterface {
    realm: string;
    errorCode: BearerTokenErrorCode;
    statusCode: number
    description: string;
    uri: string;
    challenge: string
}

class BearerTokenError implements BearerTokenErrorInterface {
}

class InvalidTokenError implements BearerTokenErrorInterface {
}

class InsufficientScopeError implements BearerTokenErrorInterface {
    scopes: Array<string>
}
```

> Note: The InsufficientScopeError will only be returned if you specified required scopes with the `scopes` and `scopesClaimName` option
