package goauth

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// JWT specific configuration
type jwtConfiguration struct {
	IssuerURI                   string `yaml:"issuerURI"`
	SigningSecret               string `yaml:"signingSecret"`
	AccessTokenDurationMinutes  int64  `yaml:"accessTokenDurationMinutes"`
	RefreshTokenDurationMinutes int64  `yaml:"refreshTokenDurationMinutes"`
	AcceptableClockSkewSeconds  int    `yaml:"acceptableClockSkewSeconds"`
}

// Issuer substitition configuration
type issuerSubstitutionConfiguration struct {
	Placeholder string `yaml:"placeholder"`
	Claim       string `yaml:"claim"`
}

// Defines an OpenID Connect provider. Some fields are filled from the YAML file, some are filled afterwards.
type oidcProviderConfiguration struct {
	// The URI to the "well-known" JSON configuration of the provider
	ConfigurationURI string `yaml:"configurationURI"`
	// When the information from the URI has been fetched, it will be stored here to prevent the need for further fetches.
	Configuration *oidcConfiguration
	// If the information from the configuration URI is incorrect or incomplete, we can override fields with this.
	ConfigurationOverrides map[string]string `yaml:"configurationOverrides"`
	// The supported scopes that we will request from that provider.
	Scopes string `yaml:"scopes"`
	// What type of auth flows are supported by this provider?
	SupportedFlows []string `yaml:"supportedFlows"`
	// For multi-tenant providers, the "issuer" claim will contain a placeholder that needs substituted with our value.
	IssuerSubstitutions []issuerSubstitutionConfiguration `yaml:"issuerSubstitutions"`
	// Does the provider support PKCE? (applicable to authorization_code flow only)
	SupportsPkce bool `yaml:"supportsPKCE"`
	// The client ID of our registered app with this provider.
	ClientID string `yaml:"clientID"`
	// The client secret of our registered app with this provider.
	ClientSecret string `yaml:"clientSecret"`
	// JSON property path to the error description in any possible error response. Usually simply "error_description",
	// unless the provider doesn't adhere to OAuth standards for some reason (bloody Facebook, innit!).
	ErrorDescriptionProperty string `yaml:"errorDescriptionProperty"`
	// JSON property path to the error type in any possible error response. Usually simply "error",
	// unless the provider doesn't adhere to OAuth standards for some reason (bloody Facebook, innit!).
	ErrorTypeProperty string `yaml:"errorTypeProperty"`
}

// Typical information contained in a provider's "well-known" JSON configuration.
type oidcConfiguration struct {
	// The base URI for this issuer/provider.
	Issuer string `json:"issuer"`
	// The URI to call when we want to initiate the actual authentication flow.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// A URI that will return an access token (and sometimes ID token), once we have an authorization code.
	TokenEndpoint string `json:"token_endpoint"`
	// A URI that will return the information about the authenticated user, given an access token.
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	// A URI that will return the JSON Web Key Sets that this provider uses to sign tokens.
	JwksURI string `json:"jwks_uri"`
}

// Endpoint strings for the various services.
type endpointConfiguration struct {
	InitiateOpenIDConnectAuthenticationEndpoint string `yaml:"initiateOpenIDConnectAuthenticationEndpoint"`
	OpenIDConnectLoginEndpoint                  string `yaml:"openIDConnectLoginEndpoint"`
	LogoutEndpoint                              string `yaml:"logoutEndpoint"`
	RefreshEndpoint                             string `yaml:"refreshEndpoint"`
	PasswordLoginEndpoint                       string `yaml:"passwordLoginEndpoint"`
}

type cookieConfiguration struct {
	AccessTokenName        string `yaml:"accessTokenName"`
	RefreshTokenName       string `yaml:"refreshTokenName"`
	AccessTokenAttributes  string `yaml:"accessTokenAttributes"`
	RefreshTokenAttributes string `yaml:"refreshTokenAttributes"`
}

type openIDConnectConfiguration struct {
	PKCECodeVerifierLength int                                  `yaml:"pkceCodeVerifierLength"`
	Providers              map[string]oidcProviderConfiguration `yaml:"providers"`
}

// Configuration is our top-level app configuration
type Configuration struct {
	Endpoints endpointConfiguration      `yaml:"endpoints"`
	Cookies   cookieConfiguration        `yaml:"cookies"`
	JWT       jwtConfiguration           `yaml:"jwt"`
	OIDC      openIDConnectConfiguration `yaml:"openIDConnect"`
}

// ReadConfigurationFromYAML reads a YAML config file into a Configuration object.
// See goauth.template.yaml for an example of a YAML file to complete.
func ReadConfigurationFromYAML(path string) (*Configuration, error) {
	filename, _ := filepath.Abs(path)
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config Configuration
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// Reads the "well-known" OpenID Connect configuration from the URL, if it hasn't been read already.
func (oidcConfig *oidcProviderConfiguration) getConfiguration() (*oidcConfiguration, error) {
	// Do we have the info already? Return that.
	if oidcConfig.Configuration != nil {
		return oidcConfig.Configuration, nil
	}
	// Otherwise, let's fetch it ...
	resp, err := http.Get(oidcConfig.ConfigurationURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Unmarshal the JSON into a map.
	var stringMap map[string]interface{}
	err = json.Unmarshal(bytes, &stringMap)
	if err != nil {
		return nil, err
	}
	// Apply any overrides.
	for overrideKey, overrideValue := range oidcConfig.ConfigurationOverrides {
		stringMap[overrideKey] = overrideValue
	}
	// Marshal the amended map back to JSON.
	var openIDConfiguration oidcConfiguration
	updatedJSON, err := json.Marshal(stringMap)
	if err == nil {
		// And finally unmarshal it AGAIN, into our configuration struct.
		err = json.Unmarshal(updatedJSON, &openIDConfiguration)
	}
	oidcConfig.Configuration = &openIDConfiguration
	return oidcConfig.Configuration, err
}

// Does this provider support the given authorization flow?
func (oidcConfig *oidcProviderConfiguration) supportsFlow(flow string) bool {
	for _, supportedFlow := range oidcConfig.SupportedFlows {
		if supportedFlow == flow {
			return true
		}
	}
	return false
}
