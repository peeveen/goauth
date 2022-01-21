package goauth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

// Generates a base-64 encoded sequence of bytes, for use as a code_verifier during PKCE authorization.
func getCodeVerifier(length int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = byte(r.Intn(255))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Generates the SHA256 hash of a given code_verifier, for use as a code_challenge during PKCE authorization.
func getCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Obtains the stored code_verifier from Redis, stored against a combination of state & nonce.
func getPkceCodeVerifier(state string, nonce string, storeAssistant StoreAssistant) (string, error) {
	value, err := storeAssistant.GetValue(fmt.Sprintf("%s%s", state, nonce))
	if err != nil {
		return "", err
	}
	return value, nil
}
