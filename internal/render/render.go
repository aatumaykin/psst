package render

import "bytes"

type Syntax uint8

const (
	SyntaxBrace Syntax = iota
	SyntaxShell
)

type Unresolved struct {
	Name   string
	Syntax Syntax
}

func isNameStart(c byte) bool {
	return c >= 'A' && c <= 'Z'
}

func isNameChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func isName(s string) bool {
	if s == "" || !isNameStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return false
		}
	}
	return true
}

func Render(tmpl []byte, values map[string][]byte) ([]byte, []Unresolved, int) {
	var out bytes.Buffer
	seen := make(map[string]bool)
	var unresolved []Unresolved
	subs := 0
	add := func(name string, syn Syntax) {
		key := string(rune(syn)) + name
		if seen[key] {
			return
		}
		seen[key] = true
		unresolved = append(unresolved, Unresolved{Name: name, Syntax: syn})
	}
	i := 0
	for i < len(tmpl) {
		c := tmpl[i]
		switch {
		case c == '{' && i+1 < len(tmpl) && tmpl[i+1] == '{':
			if end := bytes.Index(tmpl[i+2:], []byte("}}")); end >= 0 {
				inner := string(tmpl[i+2 : i+2+end])
				if v, ok := values[inner]; ok && isName(inner) {
					out.Write(v)
					subs++
				} else {
					add(inner, SyntaxBrace)
					out.Write(tmpl[i : i+2+end+2])
				}
				i += 2 + end + 2
				continue
			}
			out.WriteByte(c)
			i++
		case c == '$' && i+1 < len(tmpl) && tmpl[i+1] == '$':
			out.WriteString("$$")
			i += 2
		case c == '$' && i+1 < len(tmpl) && tmpl[i+1] == '{':
			if end := bytes.IndexByte(tmpl[i+2:], '}'); end >= 0 {
				spanEnd := i + 2 + end + 1
				inner := string(tmpl[i+2 : i+2+end])
				if v, ok := values[inner]; ok && isName(inner) {
					out.Write(v)
					subs++
				} else {
					add(inner, SyntaxShell)
					out.Write(tmpl[i:spanEnd])
				}
				i = spanEnd
				continue
			}
			out.WriteByte(c)
			i++
		case c == '$' && i+1 < len(tmpl) && isNameStart(tmpl[i+1]):
			j := i + 1
			for j < len(tmpl) && isNameChar(tmpl[j]) {
				j++
			}
			name := string(tmpl[i+1 : j])
			if v, ok := values[name]; ok {
				out.Write(v)
				subs++
			} else {
				add(name, SyntaxShell)
				out.Write(tmpl[i:j])
			}
			i = j
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.Bytes(), unresolved, subs
}
