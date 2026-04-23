package runner

import "strings"

func ExpandEnvVars(arg string, env map[string]string) string {
	result := arg

	for name, value := range env {
		result = strings.ReplaceAll(result, "${"+name+"}", value)
		result = strings.ReplaceAll(result, "$"+name, value)
	}

	return result
}
