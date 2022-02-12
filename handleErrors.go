package goauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	httperr "github.com/peeveen/httperrorhandler"
)

// Given a map (created from JSON), look for error information in the property specified by the given
// path (using heirarchical dot separator, e.g. "object.innerObject.propertyName")
func getValueByPath(errMap map[string]interface{}, path string) (string, bool) {
	components := strings.Split(path, ".")
	var parentComponentCount = len(components) - 1
	var ok bool
	for index, pathComponent := range components {
		value, found := errMap[strings.TrimSpace(pathComponent)]
		if !found {
			break
		}
		if index < parentComponentCount {
			errMap, ok = value.(map[string]interface{})
			if !ok {
				break
			}
		} else {
			result, ok := value.(string)
			if !ok {
				break
			}
			return result, true
		}
	}
	return "", false
}

// Checks the OIDC response to see if it contains error information, and returns what it finds.
func parseOidcError(oidcProviderConfig *oidcProviderConfiguration, bytes []byte) error {
	var responseMap map[string]interface{}
	err := json.Unmarshal(bytes, &responseMap)
	if err != nil {
		return err
	}
	errorTypeProperty := oidcProviderConfig.ErrorTypeProperty
	if errorTypeProperty == "" {
		errorTypeProperty = "error"
	}
	errorDescriptionProperty := oidcProviderConfig.ErrorDescriptionProperty
	if errorDescriptionProperty == "" {
		errorDescriptionProperty = "error_description"
	}
	errorTypeValue, found := getValueByPath(responseMap, errorTypeProperty)
	if found {
		errorDescriptionValue, found := getValueByPath(responseMap, errorDescriptionProperty)
		if found {
			return fmt.Errorf("%s (%s)", errorDescriptionValue, errorTypeValue)
		}
	}
	return nil
}

func handleClaimsAssistantError(e error) *httperr.Error {
	httpError, ok := e.(*httperr.Error)
	if ok {
		return httpError
	}
	return createClaimsAssistantError(e)
}

const goAuthURIOrigin = "https://github.com/peeveen/goauth/"

func getHTTPErrorType(identifier string) string {
	return fmt.Sprintf("%s%s", goAuthURIOrigin, identifier)
}

const unknownProviderErrorType = "unknownProvider"         // User has asked to authenticate with a provider that we don't know about.
const unauthorizedErrorType = "unauthorized"               // The provided credentials were invalid.
const communicationErrorType = "communicationError"        // A communications error occurred.
const malformedRequestErrorType = "malformedRequest"       // The request was invalid in some way (missing fields, or badly formed JSON, etc)
const unknownFlowTypeErrorType = "unknownFlowType"         // The requested authorization flow type is not one that we are aware of.
const unsupportedFlowTypeErrorType = "unsupportedFlowType" // The requested authorization flow type is not supported by the provider.
const storeAssistantErrorType = "storeAssistantError"      // An error occurred while attempting to use the StoreAssistant
const tokenCreationErrorType = "tokenCreation"             // An error occurred while creating/signing JWT tokens.
const internalErrorType = "internalError"                  // Some other internal error occurred.
const claimsAssistantErrorType = "claimsAssistantError"    // An error occurred during a request to the ClaimsAssistant

func createUnknownOpenIDConnectProviderError(provider string) *httperr.Error {
	return &httperr.Error{Type: getHTTPErrorType(unknownProviderErrorType), Status: http.StatusBadRequest, Detail: fmt.Sprintf("Unknown OpenID Connect provider: '%s'", provider)}
}

func createUnauthorizedError(e error, detail string) *httperr.Error {
	return httperr.Wrap(e, &httperr.Error{Type: getHTTPErrorType(unauthorizedErrorType), Status: http.StatusUnauthorized, Detail: detail})
}

func createCommunicationError(e error, detail string) *httperr.Error {
	return httperr.Wrap(e, &httperr.Error{Type: getHTTPErrorType(communicationErrorType), Status: http.StatusInternalServerError, Detail: detail})
}

func createMalformedRequestError(e error, detail string) *httperr.Error {
	return httperr.Wrap(e, &httperr.Error{Type: getHTTPErrorType(malformedRequestErrorType), Status: http.StatusBadRequest, Detail: detail})
}

func createUnknownFlowTypeError(flow string) *httperr.Error {
	return &httperr.Error{Type: getHTTPErrorType(unknownFlowTypeErrorType), Status: http.StatusBadRequest, Detail: fmt.Sprintf("Unknown authorization flow type: %s", flow)}
}

func createStoreAssistantError(e error, detail string) *httperr.Error {
	return httperr.Wrap(e, &httperr.Error{Type: getHTTPErrorType(storeAssistantErrorType), Status: http.StatusInternalServerError, Detail: detail})
}

func createTokenCreationError(e error, detail string) *httperr.Error {
	return httperr.Wrap(e, &httperr.Error{Type: getHTTPErrorType(tokenCreationErrorType), Status: http.StatusInternalServerError, Detail: detail})
}

func createInternalError(e error, detail string) *httperr.Error {
	return httperr.Wrap(e, &httperr.Error{Type: getHTTPErrorType(internalErrorType), Status: http.StatusInternalServerError, Detail: detail})
}

func createBadFlowTypeError(provider string, flow string) *httperr.Error {
	return &httperr.Error{Type: getHTTPErrorType(unsupportedFlowTypeErrorType), Status: http.StatusBadRequest, Detail: fmt.Sprintf("The provider '%s' does not support '%s' flow", provider, flow)}
}

func createClaimsAssistantError(e error) *httperr.Error {
	return httperr.Wrap(e, &httperr.Error{Type: getHTTPErrorType(claimsAssistantErrorType), Status: http.StatusInternalServerError, Detail: e.Error()})
}
