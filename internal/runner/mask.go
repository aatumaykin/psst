package runner

import (
	"bytes"
	"sort"
	"strings"
)

func MaskSecrets(text string, secrets []string) string {
	sorted := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if len(s) > 0 {
			sorted = append(sorted, s)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})
	for _, s := range sorted {
		text = strings.ReplaceAll(text, s, "[REDACTED]")
	}
	return text
}

func MaskSecretsBytes(data []byte, secrets [][]byte) []byte {
	sorted := make([][]byte, 0, len(secrets))
	for _, s := range secrets {
		if len(s) > 0 {
			sorted = append(sorted, s)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})
	result := make([]byte, len(data))
	copy(result, data)
	for _, s := range sorted {
		result = bytes.ReplaceAll(result, s, []byte("[REDACTED]"))
	}
	return result
}
