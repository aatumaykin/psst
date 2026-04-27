package vault

import (
	"fmt"
	"regexp"
)

const (
	maxSecretNameLen  = 256
	maxSecretValueLen = 4096
	maxTags           = 20
)

var secretNameRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

var tagRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func ValidateSecretName(name string) error {
	if len(name) > maxSecretNameLen {
		return fmt.Errorf("secret name too long: max %d bytes", maxSecretNameLen)
	}
	if !secretNameRegex.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: must match %s", name, secretNameRegex.String())
	}
	return nil
}

func ValidateTags(tags []string) error {
	if len(tags) > maxTags {
		return fmt.Errorf("too many tags: max %d", maxTags)
	}
	for _, t := range tags {
		if !tagRegex.MatchString(t) {
			return fmt.Errorf("invalid tag %q: must match %s", t, tagRegex.String())
		}
	}
	return nil
}
