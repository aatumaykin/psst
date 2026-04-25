package runner

import (
	"slices"
	"strings"
)

func ExpandEnvVars(arg string, env map[string][]byte) string {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })

	result := arg
	for _, name := range names {
		value := string(env[name])
		result = strings.ReplaceAll(result, "${"+name+"}", value)
		result = replaceBareVar(result, name, value)
	}

	return result
}

func replaceBareVar(s, name, value string) string {
	needle := "$" + name
	var b strings.Builder
	i := 0
	for {
		idx := strings.Index(s[i:], needle)
		if idx == -1 {
			b.WriteString(s[i:])
			break
		}
		idx += i
		after := idx + len(needle)
		if after < len(s) && isWordChar(s[after]) {
			b.WriteString(s[i : idx+1])
			i = idx + 1
			continue
		}
		b.WriteString(s[i:idx])
		b.WriteString(value)
		i = after
	}
	return b.String()
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
