# goauth

Pre-made OAuth/OpenIDConnect and general authorization hooks for webapp login.

- Currently supports Google, Facebook and Microsoft "out of the box", with authorization code or implicit flows.
- You can add more via YAML configuration.
- Automatic JWT validation, whether supplied via header or cookie.

# Typical usage

First thing to do is make up [a YAML configuration](goauth.template.yaml), and make sure to read the comments within.

Then, just wire it up to your existing backend webserver like this.

```
goAuthConfig, err := goauth.ReadConfigurationFromYAML("./goauth.yaml")
goAuthBuildParams := &goauth.BuildParameters{
	Config:          goAuthConfig,
	StoreAssistant:  goauth.NewRedisStoreAssistant(redisDb), // or roll your own
	ClaimsAssistant: (your_implementation_of_ClaimsAssistant),
	Logger:          logrus.StandardLogger(),
	ErrorHandler:    (handler for HTTP errors)
}
goAuthService, err := goauth.Build(goAuthBuildParams)
if err != nil {
	// handle it
}
router := mux.NewRouter()
goAuthService.ApplyRoutes(router)
```

goauth makes use of the [httperrorhandler](http://github.com/peeveen/httperrorhandler) package, so your `ErrorHandler` should deal with the `httperrorhandler.Error` type.

ApplyRoutes() works with the standard gorilla muxer. If you want to use another, the endpoint methods are exposed in the Service object.

To get things rolling, from your webapp:

- Navigate to the `initiateOpenIDConnectAuthenticationEndpoint` to trigger an authentication process, e.g.:
  `http://your_api_server:8080/oidcAuth?state=123456789&nonce=abcdefgh&provider=facebook&flow=authorization_code&redirect_uri=http://www.yourwebsite.com/login`
  - `provider` should match one of the providers configured in the YAML (you _have_ registered an app with that provider, haven't you?).
  - `flow` should be one of the flow types that the provider supports (again, configured in YAML).
  - `redirect_uri` should be a page in your webapp that expects to receive the appropriate OAuth parameters in the URL query.
- The client will be redirected to the appropriate third-party authentication page.
- When the third-party authentication redirects back to your webapp with a URL chock full of exciting codes and stuff, make a POST call (using axios or whatever) to the `openIDConnectLoginEndpoint`. e.g.:

```
axios.post('https://my_api_server:8080/oidcLogin', {
	id_token: idTokenFromUrlParams, // implicit flow only
	code: codeFromUrlParams, // authorization_code flow only
	state: stateFromUrlParams,
	nonce: storedNonce, // you'll get the state value in the URL params, but it's up to you to recall/calculate the associated nonce value.
	flow: 'authorization_code', // same values as before for the rest of these
	provider: 'facebook',
	redirect_uri: 'http://www.yourwebsite.com/login',
}, {
	withCredentials: true // Required for cookies!
}) .then((response) => {
	... deal with the response ...
})
```

- All being well, the response should be access and refresh tokens, in either JSON or cookies (as per configuration). Cookies will be stored automatically by your browser.
- Use the access token as the Authorization Bearer token in future calls to your API, or let the cookies take care of themselves. To make things easier, you can wrap your protected HTTP handlers with Authorized() to automatically perform token parsing and validation. The claims from the access token are passed to your handler method for you to perform any manual authorization, e.g.:

```
router.HandleFunc("/adminTask", goauth.Authorized(handleAdminTask())).Methods("GET")

func handleAdminTask() goauth.AuthorizedHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, accessClaims map[string]interface{}) {
		// If you get here, the access token is valid, and you can then do any additional enforcement.
		if accessClaims["accessLevel"] != "admin" {
			// return 403 Forbidden
		}
		...
	}
}
```

# ClaimsAssistant

Your ClaimsAssistant object must implement three methods:

```
GetClaimsForOpenIDToken(openIDClaims map[string]interface{}, tokens *goauth.Tokens) (*goauth.Claims, error)
```

This method is called when a successful OpenID Connect login has generated an ID token relating to the logged-in user. Your implementation is given the claims from that token (e.g. "sub", "email", "name"), and also any access/refresh tokens that the third-party authenticator provided. You should then return a map of claims that you want to encode into the access/refresh tokens that goauth will return to your webapp. How these claims are generated is entirely up to you (perhaps find or create user records in your own database based on the info provided, and encode the IDs of those records?).

```
GetClaimsForRefreshToken(refreshClaims map[string]interface{}) (*goauth.Claims, error)
```

This method is called when a valid call to the `refreshEndpoint` is made. The claims from the refresh token are provided to this method, and it should return a full set of claims for the new access & refresh tokens that goauth will generate. If you are encoding the same claims into the refresh & access tokens, then this method should be trivial to implement.

```
GetClaimsForPasswordLogin(username string, password string, issuer string) (*goauth.Claims, error)
```

Only called if you are using standard name+password login, via the `passwordLoginEndpoint`. Similar to the above, you must validate the login and, if valid, return a map of claims that you want to encode into the access/refresh tokens that goauth will return to your webapp. The `issuer` argument will be your own JWT issuer string, from the YAML config.

# Error handling

All goauth endpoints utilise the [httperrorhandler](http://github.com/peeveen/httperrorhandler) package, and produce [RFC-7807](https://datatracker.ietf.org/doc/html/rfc7807)-like errors.

Your ClaimsAssistant implementation can return any type of error, and it will be wrapped in an `httperrorhandler.Error` error.

Alternatively, if your implementation produces `httperrorhandler.Error` errors, these will be returned directly to the client, so if you want your webapp to capture specific types of error and respond appropriately, you might want to make use of that. For example, a user attempts a password login, but they have not yet verified themselves by clicking a link sent via email. If your `GetClaimsForPasswordLogin` method returns an `httperrorhandler.Error` with a `Type` field specific to your application, your front-end can capture that, and redirect the user to a "Re-send verification email" page.

# TODO

- Better JWT signing & validation (private & public keys instead of simply "secret string"?)
- Other ApplyRoutes() helper methods for other web server packages (gin?)
- Support more authorization flow types? Not sure, most of the others seem unsuitable for websites.
- An example client app
