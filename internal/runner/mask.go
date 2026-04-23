package runner

import "strings"

func MaskSecrets(text string, secrets []string) string {
	for _, s := range secrets {
		if len(s) > 0 {
			text = strings.ReplaceAll(text, s, "[REDACTED]")
		}
	}
	return text
}
