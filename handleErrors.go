package goauth

import (
	"encoding/json"
	"fmt"
	"strings"
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
