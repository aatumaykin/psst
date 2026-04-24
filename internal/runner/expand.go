package runner

import (
	"regexp"
	"slices"
	"strings"
)

func ExpandEnvVars(arg string, env map[string]string) string {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })

	result := arg
	for _, name := range names {
		value := env[name]
		result = strings.ReplaceAll(result, "${"+name+"}", value)

		pattern := regexp.MustCompile(`\$` + regexp.QuoteMeta(name) + `(?![A-Za-z0-9_])`)
		result = pattern.ReplaceAllString(result, value)
	}

	return result
}
