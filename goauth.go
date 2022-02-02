package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	httperr "github.com/peeveen/httperrorhandler"
	"github.com/sirupsen/logrus"
)

// AuthorizedHandlerFunc is a type for handler functions that you want to use with the Authorized
// wrapper. Standard response and request interfaces, plus the collection of claims from the
// validated access token for you to examine and determine authorization level.
type AuthorizedHandlerFunc func(http.ResponseWriter, *http.Request, map[string]interface{})

// StoreAssistant is an interface that manages the storage of temporary data. Working with
// OpenID Connect, we need to keep track of access tokens, refresh tokens, state and nonce
// values, code challenge strings, etc. You can implement this yourself, or if you want to
// use Redis, see NewRedisStoreAssistant.
type StoreAssistant interface {
	SetValue(key string, value string, duration time.Duration) error
	GetValue(key string) (string, error)
	DeleteValue(key string) error
}

// ClaimsAssistant is the interface that you will need to implement to response to successful
// logins (via OpenID Connect or via simple username/password) by returning a collection of
// "claims" (key+value pairs) that should be encoded into the resulting access and refresh
// tokens.
type ClaimsAssistant interface {
	GetClaimsForOpenIDToken(openIDClaims map[string]interface{}, tokens *Tokens) (*Claims, error)
	GetClaimsForRefreshToken(refreshClaims map[string]interface{}) (*Claims, error)
	GetClaimsForPasswordLogin(username string, password string, issuer string) (*Claims, error)
}

// Claims to encode into tokens
type Claims struct {
	AccessTokenClaims  map[string]interface{}
	RefreshTokenClaims map[string]interface{}
}

// The login request that we will expect from a client. Once the user has responded to the
// third-party authentication UI, a series of values will be returned to the client browser
// via URL arguments. The client can then make the actual "login" call to this service by
// sending this request, populated with those values.
type openIDConnectLoginBody struct {
	Tokens             // Will only be populated with implicit flow
	State       string `json:"state"`
	Nonce       string `json:"nonce"`
	Provider    string `json:"provider"`
	Flow        string `json:"flow"`
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
}

func (body *openIDConnectLoginBody) AsTokens() *Tokens {
	return &Tokens{body.AccessToken, body.RefreshToken, body.IDToken}
}

// Tokens is a typical response that we will expect from an OIDC provider when we ask for tokens during authorization_code flow.
// Depending on the request type, not all tokens in this struct will be returned.
type Tokens struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Request body for username + password login. If an unverified user attempting login is a possibility,
// you can provide a URL that we can redirect to for you to show extra UI (e.g. "Resend verification email")
type passwordLoginBody struct {
	Username                  string `json:"username"`
	Password                  string `json:"password"`
	UnverifiedUserRedirectURI string `json:"unverified_user_redirect_uri"`
}

// String identifiers for supported authorization flows.
const authorizationCodeFlowName = "authorization_code"
const implicitFlowName = "implicit"

// ErrIncorrectPassword is the error to return from ClaimsAssistant.ValidatePasswordLogin when the supplied
// password is wrong.
var ErrIncorrectPassword = errors.New("incorrect password")

// ErrUnverifiedUser is the error to return from ClaimsAssistant.ValidatePasswordLogin when the user has
// not yet verified their identity (via email link, or whatever).
var ErrUnverifiedUser = errors.New("this user is not yet verified")

// Service is the object you'll get back from Build(), containing everything you need.
// You can use the various HandlerFuncs to hook up your own router handlers.
// Or you can use the ApplyRoutes() function to do it for you.
type Service struct {
	InitiateAuthenticationHandler http.HandlerFunc
	OpenIDConnectLoginHandler     http.HandlerFunc
	PasswordLoginHandler          http.HandlerFunc
	LogoutHandler                 http.HandlerFunc
	RefreshHandler                http.HandlerFunc
	AuthorizedHandler             func(handler AuthorizedHandlerFunc) http.HandlerFunc
	ApplyRoutes                   func(router *mux.Router)
}

// BuildParameters contains everything that GoAuth needs to run.
type BuildParameters struct {
	Config          *Configuration
	StoreAssistant  StoreAssistant
	ClaimsAssistant ClaimsAssistant
	Logger          *logrus.Logger
	ErrorHandler    httperr.Handler
}

// BuildParameters, plus some stuff that we construct during Build() to save time and fuss later.
type runtimeParameters struct {
	KeySet jwk.Set
	*BuildParameters
}

func (params *runtimeParameters) getOpenIDConnectProviderInfo(provider string) (*oidcProviderConfiguration, *oidcConfiguration, *httperr.Error) {
	oidcProviderConfig, found := params.Config.OIDC.Providers[provider]
	if !found {
		return nil, nil, &httperr.Error{HTTPStatus: http.StatusBadRequest, Error: fmt.Errorf("unknown OIDC provider: '%s'", provider)}
	}
	// Get the OIDC configuration from the provider.
	openIDConfiguration, err := oidcProviderConfig.getConfiguration()
	if err != nil {
		return nil, nil, &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
	}
	return &oidcProviderConfig, openIDConfiguration, nil
}

// Build generates the GoAuth service object from the given configurations and helper interfaces.
func Build(buildParams *BuildParameters) (*Service, error) {
	// Generate JWT signing & validation keys and keysets.
	jwkKeySet := jwk.NewSet()
	jwkKey, err := jwk.New([]byte(buildParams.Config.JWT.SigningSecret))
	jwkKey.Set(jwk.AlgorithmKey, jwa.HS256)
	jwk.AssignKeyID(jwkKey)
	if err != nil {
		return nil, err
	}
	jwkKeySet.Add(jwkKey)
	runtimeParams := &runtimeParameters{
		KeySet:          jwkKeySet,
		BuildParameters: buildParams,
	}

	// Create handler functions.
	initiateAuthenticationHandler := handleOidcAuth(runtimeParams)
	openIDConnectLoginHandler := handleOidcLogin(runtimeParams)
	passwordLoginHandler := handlePasswordLogin(runtimeParams)
	logoutHandler := Authorized(handleLogout(runtimeParams), runtimeParams)
	refreshHandler := handleRefresh(runtimeParams)
	authorizedHandler := func(handler AuthorizedHandlerFunc) http.HandlerFunc { return Authorized(handler, runtimeParams) }

	// Build the final response object.
	svc := Service{
		InitiateAuthenticationHandler: initiateAuthenticationHandler,
		OpenIDConnectLoginHandler:     openIDConnectLoginHandler,
		PasswordLoginHandler:          passwordLoginHandler,
		LogoutHandler:                 logoutHandler,
		RefreshHandler:                refreshHandler,
		AuthorizedHandler:             authorizedHandler,
		ApplyRoutes: func(router *mux.Router) {
			router.HandleFunc(buildParams.Config.Endpoints.InitiateOpenIDConnectAuthenticationEndpoint, initiateAuthenticationHandler).Methods("GET")

			router.HandleFunc(buildParams.Config.Endpoints.OpenIDConnectLoginEndpoint, openIDConnectLoginHandler).Methods("POST")
			router.HandleFunc(buildParams.Config.Endpoints.LogoutEndpoint, logoutHandler).Methods("POST")
			router.HandleFunc(buildParams.Config.Endpoints.RefreshEndpoint, refreshHandler).Methods("POST")

			// If password login is enabled, enable that endpoint.
			if buildParams.Config.Endpoints.PasswordLoginEndpoint != "" {
				router.HandleFunc(fmt.Sprintf("/%s", buildParams.Config.Endpoints.PasswordLoginEndpoint), passwordLoginHandler).Methods("POST")
			}
		},
	}

	return &svc, nil
}

// Initiates the OIDC authentication process by redirecting the browser to the third-party authentication page, with
// various appropriate URL args set.
func handleOidcAuth(params *runtimeParameters) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httperr.Handle(w, r, func(w http.ResponseWriter, r *http.Request) *httperr.Error {
			// On this endpoint, the values are supplied as URL parameters.
			provider := r.URL.Query().Get("provider")
			state := r.URL.Query().Get("state")
			flow := r.URL.Query().Get("flow")
			nonce := r.URL.Query().Get("nonce")
			redirectURI := r.URL.Query().Get("redirect_uri")
			// OK, find out what provider we're using ...
			oidcProviderConfig, openIDConfiguration, err := params.getOpenIDConnectProviderInfo(provider)
			if err != nil {
				return err
			}
			// ... and make sure it supports the request authorization flow type.
			if !oidcProviderConfig.supportsFlow(flow) {
				return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: fmt.Errorf("the provider '%s' does not support '%s' flow", provider, flow)}
			}
			// If using implicit flow type, we simply request the id_token outright. This returns the id_token information to the client browser.
			// If using authorization_code flow type, we request an authorization code that we will use later to obtain tokens. The authorization code
			// is of no use to any bad actors at the client side, as it is will never be accepted by the authentication provider without the client
			// secret AND (if supported) the randomly-generated PKCE code verifier.
			var responseType string
			var codeChallengeParam string = ""
			if flow == implicitFlowName {
				responseType = "id_token"
			} else if flow == authorizationCodeFlowName {
				responseType = "code"
				// If the provider supports PKCE, we can add an extra layer of security.
				// The authorization code that the provider will give us will (usually) only be useful to those who know the "client secret" of the
				// app that we registered with that provider. It's unlikely that any attacker will obtain that client secret, but just in case, PKCE
				// can provide another hurdle. We send the provider a "code_challenge" value, which is the SHA256 hash of a randomly-generated
				// sequence of bytes. When requesting an access token later, we must also provide a code_verifier, which is the sequence of bytes
				// that the code_challenge hash was derived from. The code_challenge hash WILL be visible to the client browser, but it is
				// extremely unlikely that an attacker could calculate a matching code_verifier in time.
				if oidcProviderConfig.SupportsPkce {
					codeVerifier := getCodeVerifier(params.Config.OIDC.PKCECodeVerifierLength)
					codeChallenge := getCodeChallenge(codeVerifier)
					// Store the code verifier in Redis. We will need it later. Store it against the state & nonce.
					err := params.StoreAssistant.SetValue(fmt.Sprintf("%s%s", state, nonce), codeVerifier, time.Hour)
					if err != nil {
						return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
					}
					codeChallengeParam = fmt.Sprintf("&code_challenge=%s&code_challenge_method=S256", codeChallenge)
				}
			} else {
				return &httperr.Error{HTTPStatus: http.StatusBadRequest, Error: fmt.Errorf("unknown authorization flow type: %s", flow)}
			}
			// Redirect the client browser to the provider's authorization endpoint URI, loaded up with our relevant URL query parameters.
			authURL := fmt.Sprintf("%s?nonce=%s&scope=%s&state=%s&response_type=%s&client_id=%s&redirect_uri=%s%s%s",
				openIDConfiguration.AuthorizationEndpoint,
				nonce,
				oidcProviderConfig.Scopes,
				state,
				responseType,
				oidcProviderConfig.ClientID,
				redirectURI,
				codeChallengeParam,
				oidcProviderConfig.CustomAuthParameters)
			w.Header().Set("Location", authURL)
			w.WriteHeader(http.StatusFound)
			return nil
		}, params.ErrorHandler)
	}
}

// If the OIDC authentication loop has completed successfully (i.e. user has managed to login to third-party provider), our webapp
// will have received a bunch of URL arguments with an authorization code or id token amongst them. The webapp makes a POST to this
// method to (hopefully) get back access and refresh tokens.
func handleOidcLogin(params *runtimeParameters) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httperr.Handle(w, r, func(w http.ResponseWriter, r *http.Request) *httperr.Error {
			// First, get the login info that we have been POSTed.
			var loginBody openIDConnectLoginBody
			defer r.Body.Close()
			err := json.NewDecoder(r.Body).Decode(&loginBody)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusBadRequest, Error: err}
			}
			// OK, find out what provider we're using ...
			oidcProviderConfig, openIDConfiguration, httpErr := params.getOpenIDConnectProviderInfo(loginBody.Provider)
			if httpErr != nil {
				return httpErr
			}
			// Depending on the flow type, we will ...
			if loginBody.Flow == implicitFlowName {
				// ... already have an id_token, so go ahead and login with those details.
				return loginWithIDToken(w, r, oidcProviderConfig, openIDConfiguration, loginBody.AsTokens(), loginBody.Nonce, params)
			} else if loginBody.Flow == authorizationCodeFlowName {
				// ... have an authorization code. We can request access/id tokens from the provider using that code,
				// along with our client secret, and (optionally) our PKCE code verifier.
				return loginWithAuthorizationCode(w, r, oidcProviderConfig, openIDConfiguration, &loginBody, params)
			} else {
				return &httperr.Error{HTTPStatus: http.StatusBadRequest, Error: fmt.Errorf("unknown authorization flow type: %s", loginBody.Flow)}
			}
		}, params.ErrorHandler)
	}
}

// Given a refresh token, this function will validate it, and if valid, it will extract the user name, and generate a new access token and refresh
// token for that user. If successful, the old refresh token will no longer be valid.
func handleRefresh(params *runtimeParameters) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httperr.Handle(w, r, func(w http.ResponseWriter, r *http.Request) *httperr.Error {
			refreshToken, err := getHeaderToken(r, params.Config.Cookies.RefreshTokenName)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: err}
			}
			// Does Redis have a record of this refresh token? If not,
			// then it's an unauthorized request.
			accessToken, err := params.StoreAssistant.GetValue(refreshToken)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: fmt.Errorf("refresh token was not found, or has expired. Err: %s", err)}
			}
			// Validate the token, and get the user claims from it.
			refreshTokenClaims, err := parseAndValidateToken(refreshToken, params.KeySet, params.Config.JWT.IssuerURI)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: err}
			}
			claims, err := params.ClaimsAssistant.GetClaimsForRefreshToken(refreshTokenClaims)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
			}
			// The old access token and refresh token are no longer valid.
			params.StoreAssistant.DeleteValue(accessToken)
			params.StoreAssistant.DeleteValue(refreshToken)
			return handleSuccessfulLogin(w, r, claims, params)
		}, params.ErrorHandler)
	}
}

// Given an access token, this function will invalidate it, as well as the associated refresh token. Further API calls with either of these tokens
// will be unauthorized.
// It's not strictly necessary to perform logout: you could simply delete/forget the access and refresh tokens from the browser local storage.
// However, just in case some attacker has managed to get their hands on your tokens, and can somehow get around the CORS restrictions, you might
// want to take the nuclear option and call this.
func handleLogout(params *runtimeParameters) AuthorizedHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, accessClaims map[string]interface{}) {
		httperr.Handle(w, r, func(w http.ResponseWriter, r *http.Request) *httperr.Error {
			// Our StoreAssistant should have a refresh token associated with this access token.
			// Let's invalidate (remove) it.
			accessToken, err := getHeaderToken(r, params.Config.Cookies.AccessTokenName)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: err}
			}
			refreshToken, err := params.StoreAssistant.GetValue(accessToken)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: fmt.Errorf("no refresh token associated with access token. Err: %s", err)}
			}
			params.Logger.Debug("Invalidating access token: ", accessToken)
			params.StoreAssistant.DeleteValue(accessToken)
			params.Logger.Debug("Invalidating refresh token: ", refreshToken)
			params.StoreAssistant.DeleteValue(refreshToken)
			return nil
		}, params.ErrorHandler)
	}
}

// Given a username and password, this function will ask the ClaimsAssistant to authenticate those credentials, and if valid,
// it will generate a new access token and refresh token for that user.
// The ClaimsAssistant should return ErrUnverifiedUser if an unverified (i.e. pending verification) user is attempting to login.
// The ClaimsAssistant should return ErrIncorrectPassword if the password is wrong.
func handlePasswordLogin(params *runtimeParameters) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httperr.Handle(w, r, func(w http.ResponseWriter, r *http.Request) *httperr.Error {
			var loginBody passwordLoginBody
			defer r.Body.Close()
			err := json.NewDecoder(r.Body).Decode(&loginBody)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusBadRequest, Error: err}
			}
			userClaims, err := params.ClaimsAssistant.GetClaimsForPasswordLogin(loginBody.Username, loginBody.Password, params.Config.JWT.IssuerURI)
			if err == ErrUnverifiedUser {
				if loginBody.UnverifiedUserRedirectURI != "" {
					// An unverified user has attempted to login without first verifying their email via the link that they should have been sent.
					// Redirect to the provided redirection URI.
					w.Header().Set("Location", loginBody.UnverifiedUserRedirectURI)
					w.WriteHeader(http.StatusFound)
					return nil
				}
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: err}
			} else if err == ErrIncorrectPassword {
				// Does the password match the one provided?
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: err}
			} else if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
			}
			// At this point, we are satisfied.
			return handleSuccessfulLogin(w, r, userClaims, params)
		}, params.ErrorHandler)
	}
}

// Authorized only lets the request proceed if a valid access token is provided in the request header.
func Authorized(h AuthorizedHandlerFunc, params *runtimeParameters) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var accessClaims map[string]interface{}
		httperr.Handle(w, r, func(w http.ResponseWriter, r *http.Request) *httperr.Error {
			accessToken, err := getHeaderToken(r, params.Config.Cookies.AccessTokenName)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: err}
			}
			accessClaims, err = parseAndValidateToken(accessToken, params.KeySet, params.Config.JWT.IssuerURI)
			if err != nil {
				return &httperr.Error{HTTPStatus: http.StatusUnauthorized, Error: fmt.Errorf("failed to validate access token. Err: %s", err)}
			}
			return nil
		}, params.ErrorHandler)
		h(w, r, accessClaims)
	}
}

// Extracts the access or refresh token from the header of the request.
// Could be in the "Authorization: Bearer" header, or in a cookie.
func getHeaderToken(r *http.Request, cookieName string) (string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	authorizationHeaderParts := strings.Fields(authorizationHeader)
	if len(authorizationHeaderParts) != 2 || authorizationHeaderParts[1] == "" {
		if cookieName != "" {
			accessTokenCookie, err := r.Cookie(cookieName)
			if err == nil {
				return accessTokenCookie.Value, nil
			}
		}
		return "", fmt.Errorf("no bearer token found in request")
	}
	return authorizationHeaderParts[1], nil
}

// Parses the response from the OIDC provider when we ask for access/id tokens.
// The structure of the data received will be different, depending on success or failure.
func parseOidcResponse(oidcProviderConfig *oidcProviderConfiguration, body io.ReadCloser, output interface{}, logger *logrus.Logger) error {
	bytes, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	logger.Debug(fmt.Sprintf("decoded OIDC response: %s", string(bytes)))
	// Does the response describe an error?
	err = parseOidcError(oidcProviderConfig, bytes)
	if err != nil {
		return err
	}
	// Otherwise, parse as the expected response type.
	return json.Unmarshal(bytes, &output)
}

// Used during authorization_code flow. We need to exchange the authorization code we received for an access or id token.
func loginWithAuthorizationCode(w http.ResponseWriter, r *http.Request, oidcProviderConfig *oidcProviderConfiguration, openIDConfiguration *oidcConfiguration, loginBody *openIDConnectLoginBody, params *runtimeParameters) *httperr.Error {
	// POST our token request to the provider's token endpoint.
	postData := url.Values{}
	postData.Add("client_id", oidcProviderConfig.ClientID)
	postData.Add("client_secret", oidcProviderConfig.ClientSecret)
	postData.Add("grant_type", authorizationCodeFlowName)
	postData.Add("code", loginBody.Code)
	if loginBody.RedirectURI != "" {
		postData.Add("redirect_uri", loginBody.RedirectURI)
	}
	// If PKCE is involved, add our code verifier. We will have stored it in Redis.
	if oidcProviderConfig.SupportsPkce {
		codeVerifier, err := getPkceCodeVerifier(loginBody.State, loginBody.Nonce, params.StoreAssistant)
		if err == nil {
			postData.Add("code_verifier", codeVerifier)
		} else {
			params.Logger.Debug(fmt.Sprintf("No code verifier stored for key '%s%s'", loginBody.State, loginBody.Nonce))
		}
	}
	tokenResponse, err := http.PostForm(openIDConfiguration.TokenEndpoint, postData)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
	}
	defer tokenResponse.Body.Close()
	// Parse the response (it might be an error if any of the verification codes are wrong).
	var tokenBody Tokens
	err = parseOidcResponse(oidcProviderConfig, tokenResponse.Body, &tokenBody, params.Logger)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
	}
	// If all is well, we will have an ID token, which we can go ahead and log in with.
	return loginWithIDToken(w, r, oidcProviderConfig, openIDConfiguration, &tokenBody, loginBody.Nonce, params)
}

// Once we receive the id_token, we have to validate it, in case some attacker is trying to push a made-up identity onto us.
// Fortunately, JWT ID tokens are signed, and only the provider's key set contains the keys that can be used to validate that signature.
func loginWithIDToken(w http.ResponseWriter, r *http.Request, oidcProviderConfig *oidcProviderConfiguration, openIDConfiguration *oidcConfiguration, tokens *Tokens, nonce string, params *runtimeParameters) *httperr.Error {
	// The JWT id token will signed with a private key. We need the public keys from the
	// provider in order to validate the JWT. They provide them in JSON format via a standard
	// URI that is part of their Open ID Connect configuration.
	params.Logger.Debug(fmt.Sprintf("Retrieving keys from %s", openIDConfiguration.JwksURI))
	set, err := jwk.Fetch(context.Background(), openIDConfiguration.JwksURI)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
	}
	params.Logger.Debug(fmt.Sprintf("Retrieved %d keys from %s", set.Len(), openIDConfiguration.JwksURI))
	jwtBytes := []byte(tokens.IDToken)

	// We have to do this bit because of Microsoft, but other multi-tenant authorities might get
	// added in the future ...
	// In the upcoming JWT validation call, we can't always use a simple:
	//     jwt.WithIssuer(openIdConfiguration.Issuer)
	// to verify that the issuer is correct, because Microsoft put stupid {tenantid} placeholders
	// in their issuer ID, so we have to roll our own validation function. The oidc_providers.yaml file
	// defines the placeholders, and which JWT token claims to replace them with.
	issuerValidationFunction := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
		issuerWithSubstitutions := openIDConfiguration.Issuer
		for _, subst := range oidcProviderConfig.IssuerSubstitutions {
			claimValue, ok := t.Get(subst.Claim)
			if !ok {
				return fmt.Errorf("expected token to have '%s' value", subst.Claim)
			}
			claimString := claimValue.(string)
			params.Logger.Debugf("Substituting '%s' in issuer string with '%s'.", subst.Placeholder, claimString)
			issuerWithSubstitutions = strings.Replace(issuerWithSubstitutions, subst.Placeholder, claimString, 1)
		}
		issuerFromToken := t.Issuer()
		if issuerFromToken != issuerWithSubstitutions {
			return fmt.Errorf("issuer from token (%s) does not match expected issuer (%s)", issuerFromToken, issuerWithSubstitutions)
		}
		return nil
	})

	params.Logger.Debug("Parsing and validating ID token from issuer.")
	parsingOptions := []jwt.ParseOption{
		// We want an error back if any of the validation options fail.
		jwt.WithValidate(true),
		// Here are the keys that can be used to validate the token.
		// A key selector function (internal to the jwt package) will
		// choose the key that matches the "kid" (key ID) and
		// "alg" (signing algorithm) in the JWT header.
		jwt.WithKeySet(set),
		// The "aud" (Audience) value in token should be our Client ID.
		jwt.WithAudience(oidcProviderConfig.ClientID),
		// Annoyingly, Microsoft's keys don't have an "alg" value (telling
		// us the signing algorithm), so the key selector will fall over
		// without this little nudge.
		jwt.InferAlgorithmFromKey(true),
		// Sometimes we get tokens that claim to have been issued at a
		// time a few seconds in the future, and the validation will
		// fail unless we allow for some clock skew.
		jwt.WithAcceptableSkew(time.Second * time.Duration(params.Config.JWT.AcceptableClockSkewSeconds)),
		// Make sure the issuer of this JWT matches the expected issuer
		// by calling our own issuer validation function.
		jwt.WithValidator(issuerValidationFunction),
	}
	if nonce != "" {
		// There should be a claim in the JWT payload that matches the
		// "nonce" value that we provided back when we initiated the
		// authentication process (back in handleOidcAuth).
		parsingOptions = append(parsingOptions, jwt.WithClaimValue("nonce", nonce))
	}
	parsedToken, err := jwt.Parse(
		jwtBytes,
		parsingOptions...,
	)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
	}
	// At this point, we are satisfied.
	params.Logger.Debug("Successfully parsed ID token.")
	parsedTokenClaims, err := parsedToken.AsMap(context.Background())
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
	}
	userClaims, err := params.ClaimsAssistant.GetClaimsForOpenIDToken(parsedTokenClaims, tokens)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: err}
	}
	// Okay, we now know that there is a valid login record (associated
	// with the OpenID Connect "subject" & issuer), and that login
	// record points to a user in our system, so we can go ahead and
	// give them access tokens. We're happy!
	return handleSuccessfulLogin(w, r, userClaims, params)
}

// Function shared by a successful login, and also a refresh token re-authentication.
// Returns access and refresh tokens to the client.
func handleSuccessfulLogin(w http.ResponseWriter, r *http.Request, userClaims *Claims, params *runtimeParameters) *httperr.Error {
	// Generate some fresh tokens.
	claimsLogger := func(claims map[string]interface{}) {
		for k, v := range claims {
			params.Logger.Debug(fmt.Sprintf("\t%s = %s", k, v))
		}
	}
	params.Logger.Debug("Access token claims to encode ...")
	claimsLogger(userClaims.AccessTokenClaims)
	params.Logger.Debug("Refresh token claims to encode ...")
	claimsLogger(userClaims.RefreshTokenClaims)

	accessToken, accessTokenDuration, err := createSignedAccessToken(userClaims.AccessTokenClaims, params.Config.JWT, params.KeySet)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: fmt.Errorf("failed to create access JWT. Err: %s", err)}
	}
	refreshToken, refreshTokenDuration, err := createSignedRefreshToken(userClaims.RefreshTokenClaims, params.Config.JWT, params.KeySet)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: fmt.Errorf("failed to create JWT. Err: %s", err)}
	}
	// Set up the Redis data for this login.
	// Associate the access token with the refresh token. This is so that, if the user explicitly
	// logs out (using the access token), we can invalidate the corresponding refresh token.
	err = params.StoreAssistant.SetValue(accessToken, refreshToken, accessTokenDuration)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: fmt.Errorf("failed to store access token. Err: %s", err)}
	}
	params.Logger.Debug("Added access token to Redis: ", accessToken)
	// Also keep the refresh token, and associate it with the access token
	err = params.StoreAssistant.SetValue(refreshToken, accessToken, refreshTokenDuration)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: fmt.Errorf("failed to store refresh token. Err: %s", err)}
	}
	params.Logger.Debug("Added refresh token to Redis: ", refreshToken)

	tokens := Tokens{}
	if params.Config.Cookies.AccessTokenName == "" {
		tokens.AccessToken = accessToken
	} else {
		w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; %s", params.Config.Cookies.AccessTokenName, accessToken, int(accessTokenDuration.Seconds()), params.Config.Cookies.AccessTokenAttributes))
	}
	if params.Config.Cookies.RefreshTokenName == "" {
		tokens.RefreshToken = refreshToken
	} else {
		w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Path=%s; %s", params.Config.Cookies.RefreshTokenName, refreshToken, int(refreshTokenDuration.Seconds()), params.Config.Endpoints.RefreshEndpoint, params.Config.Cookies.RefreshTokenAttributes))
	}
	params.Logger.Debug("Returning login tokens: ", tokens)
	jsonResp, err := json.Marshal(tokens)
	if err != nil {
		return &httperr.Error{HTTPStatus: http.StatusInternalServerError, Error: fmt.Errorf("failed to marshal JSON response. Err: %s", err)}
	}
	w.Write(jsonResp)
	return nil
}
