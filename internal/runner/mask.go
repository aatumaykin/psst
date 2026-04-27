package runner

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

func MaskSecrets(text string, secrets []string) string {
	if len(secrets) == 0 {
		return text
	}

	sorted := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if len(s) > 0 {
			sorted = append(sorted, s)
		}
	}
	if len(sorted) == 0 {
		return text
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})

	markers := make([]string, len(sorted))
	for i := range sorted {
		markers[i] = fmt.Sprintf("\x00PSST_MASK_%d\x00", i)
	}

	for i, s := range sorted {
		text = strings.ReplaceAll(text, s, markers[i])
	}
	for _, m := range markers {
		text = strings.ReplaceAll(text, m, "[REDACTED]")
	}
	return text
}

func MaskSecretsBytes(data []byte, secrets [][]byte) []byte {
	if len(secrets) == 0 {
		return data
	}

	sorted := make([][]byte, 0, len(secrets))
	for _, s := range secrets {
		if len(s) > 0 {
			sorted = append(sorted, s)
		}
	}
	if len(sorted) == 0 {
		return data
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})

	markers := make([][]byte, len(sorted))
	for i := range sorted {
		markers[i] = []byte(fmt.Sprintf("\x00PSST_MASK_%d\x00", i))
	}

	result := make([]byte, len(data))
	copy(result, data)

	for i, s := range sorted {
		result = bytes.ReplaceAll(result, s, markers[i])
	}
	for _, m := range markers {
		result = bytes.ReplaceAll(result, m, []byte("[REDACTED]"))
	}

	return result
}
