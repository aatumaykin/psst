package runner

import (
	"slices"
	"strings"
)

func ExpandEnvVars(arg string, env map[string][]byte) string {
	if len(env) == 0 {
		return arg
	}

	type pattern struct {
		brace string
		bare  string
		value string
	}

	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })

	patterns := make([]pattern, len(names))
	for i, name := range names {
		patterns[i] = pattern{
			brace: "${" + name + "}",
			bare:  "$" + name,
			value: string(env[name]),
		}
	}

	var b strings.Builder
	i := 0
	for i < len(arg) {
		matched := false
		for _, p := range patterns {
			if strings.HasPrefix(arg[i:], p.brace) {
				b.WriteString(p.value)
				i += len(p.brace)
				matched = true
				break
			}
			if strings.HasPrefix(arg[i:], p.bare) {
				after := i + len(p.bare)
				if after >= len(arg) || !isWordChar(arg[after]) {
					b.WriteString(p.value)
					i = after
					matched = true
					break
				}
			}
		}
		if !matched {
			b.WriteByte(arg[i])
			i++
		}
	}
	return b.String()
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
