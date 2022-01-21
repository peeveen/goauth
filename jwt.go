package goauth

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
)

// Generates a signed JWT containing the given claims (plus standard expiry and issuer claims).
func createSignedToken(claims map[string]interface{}, duration time.Duration, jwtConfig jwtConfiguration, signingKeys jwk.Set) (string, error) {
	signingKey, ok := signingKeys.Get(0)
	if !ok {
		return "", fmt.Errorf("no signing keys in key set")
	}
	token := jwt.New()
	tokenExpiresAt := time.Now().Add(duration).Unix()
	for claimKey, claimValue := range claims {
		token.Set(claimKey, claimValue)
	}
	token.Set(jwt.ExpirationKey, tokenExpiresAt)
	token.Set(jwt.IssuerKey, jwtConfig.IssuerURI)
	signedKey, err := jwt.Sign(token, jwa.HS256, signingKey)
	if err != nil {
		return "", err
	}
	return string(signedKey), nil
}

func createSignedAccessToken(userClaims map[string]interface{}, jwtConfig jwtConfiguration, keys jwk.Set) (string, time.Duration, error) {
	duration := time.Duration(jwtConfig.AccessTokenDurationMinutes) * time.Minute
	token, err := createSignedToken(userClaims, duration, jwtConfig, keys)
	return token, duration, err
}

func createSignedRefreshToken(userClaims map[string]interface{}, jwtConfig jwtConfiguration, keys jwk.Set) (string, time.Duration, error) {
	duration := time.Duration(jwtConfig.RefreshTokenDurationMinutes) * time.Minute
	token, err := createSignedToken(userClaims, duration, jwtConfig, keys)
	return token, duration, err
}

// Checks if the given token is valid and returns the claims contained within.
func parseAndValidateToken(refreshToken string, keySet jwk.Set, issuer string) (map[string]interface{}, error) {
	parsedToken, err := jwt.Parse([]byte(refreshToken), jwt.WithKeySet(keySet))
	if err != nil {
		logrus.Debug("Could not parse JWT claims.")
		return nil, err
	}
	err = jwt.Validate(parsedToken, jwt.WithIssuer(issuer))
	if err != nil {
		logrus.Debug("Could not validate JWT claims", err)
		return nil, err
	}
	tokenClaims, err := parsedToken.AsMap(context.Background())
	if err != nil {
		return nil, err
	}
	return tokenClaims, nil
}
