# `psst render` (Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `psst render` — single-pass substitution of vault secrets into a template file (`{{KEY}}` / `$KEY` / `${KEY}` syntaxes), written out as a 0600 file, plus the recipes documentation.

**Architecture:** New leaf package `internal/render` (pure byte-level matcher, zero internal imports) + `internal/cli/render.go` command consuming it through the standard read path (`getUnlockedVault`). Render before write: unresolved placeholders → exit 1 with zero bytes written; fd-chmod 0600 BEFORE the single write. Spec: `docs/superpowers/specs/2026-09-12-render-design.md` (approved after 2 review rounds — read it before starting).

**Tech Stack:** Go 1.26 stdlib only. Existing deps only. No new dependencies.

## Global Constraints

- Tests run ONLY with `PSST_NO_KEYCHAIN=1` (use `make test`; it exports the var).
- `make test` green before every commit; conventional commits (`feat:`, `docs:`).
- No new dependencies (`go.mod` untouched). No comments in code (only `//nolint:`).
- Error wrapping: `fmt.Errorf("context: %w", err)`.
- Secret values never on stdout/stderr/logs; the ONLY output channel is the 0600 file. Test secrets are fakes (`"secret123"`, `"test-password"`).
- Work in worktree `.worktrees/render`, branch `feat/render`.
- Module path: `github.com/aatumaykin/psst`.

---

### Task 1: `internal/render` — single-pass matcher

**Files:**
- Create: `internal/render/render.go`
- Test: `internal/render/render_test.go`

**Interfaces:**
- Produces:
  - `type Syntax uint8`; `const ( SyntaxBrace Syntax = iota; SyntaxShell )`
  - `type Unresolved struct { Name string; Syntax Syntax }`
  - `func Render(tmpl []byte, values map[string][]byte) (out []byte, unresolved []Unresolved, substitutions int)` — pure; `unresolved` deduplicated, first-occurrence order.

- [ ] **Step 1: Write failing tests**

```go
package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderSyntaxes(t *testing.T) {
	values := map[string][]byte{"API_KEY": []byte("secret123"), "DB_PASS": []byte("test-password")}
	tests := []struct {
		in   string
		want string
		subs int
	}{
		{"{{API_KEY}}", "secret123", 1},
		{"$API_KEY", "secret123", 1},
		{"${API_KEY}", "secret123", 1},
		{"pw={{DB_PASS}} host=$API_KEY x=${DB_PASS}", "pw=test-password host=secret123 x=test-password", 3},
		{"plain text", "plain text", 0},
		{"{{API_KEY}}{{API_KEY}}", "secret123secret123", 2},
	}
	for _, tt := range tests {
		out, _, subs := Render([]byte(tt.in), values)
		if string(out) != tt.want || subs != tt.subs {
			t.Errorf("Render(%q) = %q, %d; want %q, %d", tt.in, out, subs, tt.want, tt.subs)
		}
	}
}

func TestRenderSinglePass(t *testing.T) {
	values := map[string][]byte{
		"A": []byte("$B ${B} {{B}}"),
		"B": []byte("must-not-appear"),
	}
	out, _, subs := Render([]byte("{{A}}"), values)
	if string(out) != "$B ${B} {{B}}" {
		t.Fatalf("single-pass violated: %q", out)
	}
	if subs != 1 {
		t.Fatalf("subs = %d, want 1", subs)
	}
}

func TestRenderUnresolvedBraceAlwaysReported(t *testing.T) {
	values := map[string][]byte{"API_KEY": []byte("secret123")}
	out, unresolved, _ := Render([]byte("{{API_KEY}} {{MISSING}} {{api_key}} {{}} {{ .Values.x }}"), values)
	if string(out) != "secret123 {{MISSING}} {{api_key}} {{}} {{ .Values.x }}" {
		t.Fatalf("unresolved braces stay literal: %q", out)
	}
	if len(unresolved) != 4 {
		t.Fatalf("unresolved = %v, want 4 entries", unresolved)
	}
	if unresolved[0].Name != "MISSING" || unresolved[0].Syntax != SyntaxBrace {
		t.Fatalf("first unresolved = %+v", unresolved[0])
	}
}

func TestRenderUnresolvedDedupOrder(t *testing.T) {
	_, unresolved, _ := Render([]byte("{{B}} {{A}} {{B}} $A ${A}"), map[string][]byte{})
	if len(unresolved) != 4 {
		t.Fatalf("unresolved = %v, want B,A brace + A shell deduped", unresolved)
	}
	want := []struct {
		name string
		syn  Syntax
	}{
		{"B", SyntaxBrace}, {"A", SyntaxBrace}, {"A", SyntaxShell}, {"A", SyntaxShell},
	}
	for i, w := range want {
		if unresolved[i].Name != w.name || unresolved[i].Syntax != w.syn {
			t.Fatalf("unresolved[%d] = %+v, want %s/%d", i, unresolved[i], w.name, w.syn)
		}
	}
}

func TestRenderShellBoundaries(t *testing.T) {
	values := map[string][]byte{"API": []byte("short")}
	tests := []struct{ in, want string }{
		{"$API_KEY", "$API_KEY"},
		{"$API", "short"},
		{"$$KEY", "$$KEY"},
		{"$$", "$$"},
		{"$1", "$1"},
		{"$lower", "$lower"},
		{"$_x", "$x"},
		{"cost$", "cost$"},
		{"${VAR:-x}", "${VAR:-x}"},
		{"${MISSING}", "${MISSING}"},
		{"${", "${"},
		{"{{", "{{"},
		{"a}}b{{OTHER}}", "a}}b{{OTHER}}"},
	}
	for _, tt := range tests {
		out, unresolved, _ := Render([]byte(tt.in), values)
		if string(out) != tt.want {
			t.Errorf("Render(%q) = %q, want %q", tt.in, out, tt.want)
		}
		if len(unresolved) != 0 {
			t.Errorf("Render(%q) unresolved = %v, want none", tt.in, unresolved)
		}
	}
}

func TestRenderShellUnresolvedReported(t *testing.T) {
	_, unresolved, _ := Render([]byte("$HOME ${MISSING}"), map[string][]byte{})
	if len(unresolved) != 2 {
		t.Fatalf("unresolved = %v", unresolved)
	}
	if unresolved[0].Name != "HOME" || unresolved[0].Syntax != SyntaxShell {
		t.Fatalf("first = %+v", unresolved[0])
	}
	if unresolved[1].Name != "MISSING" || unresolved[1].Syntax != SyntaxShell {
		t.Fatalf("second = %+v", unresolved[1])
	}
}

func TestRenderMaximalRun(t *testing.T) {
	values := map[string][]byte{"API": []byte("a"), "API_KEY": []byte("b")}
	out, subs := mustRender(t, "$API_KEY then $API", values)
	if out != "b then a" || subs != 2 {
		t.Fatalf("out = %q subs = %d", out, subs)
	}
}

func mustRender(t *testing.T, in string, values map[string][]byte) (string, int) {
	t.Helper()
	out, _, subs := Render([]byte(in), values)
	return string(out), subs
}

func TestRenderBytePreservation(t *testing.T) {
	val := []byte{0xff, 0xfe, 'x'}
	out, _, subs := Render([]byte("a{{K}}b"), map[string][]byte{"K": val})
	if !bytes.Equal(out, []byte{'a', 0xff, 0xfe, 'x', 'b'}) || subs != 1 {
		t.Fatalf("bytes = %x", out)
	}
	if strings.ContainsRune(string(out), 0) == false && len(out) != 5 {
		t.Fatal("length drift")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/render/ -v`
Expected: FAIL — `Render undefined` (package does not compile).

- [ ] **Step 3: Implement**

`internal/render/render.go`:

```go
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
				if v, ok := values[inner]; ok {
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
				if v, ok := values[inner]; ok {
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
```

Note: unresolved braces AND unresolved shell spans are both written literally into `out` — the CLI decides (by strictness) whether to error; on error the output is discarded, on non-strict success the literals are exactly what ships.

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/render/ -v && make test`
Expected: PASS (check `TestRenderShellBoundaries` case `$_x` carefully: `$_` is literal `$_`, then `x` is literal — want `"$_x"`; adjust the want string if your reading differs from the table BEFORE changing code).

- [ ] **Step 5: Commit**

```bash
git add internal/render/
git commit -m "feat: single-pass template render matcher"
```

---

### Task 2: `psst render` command

**Files:**
- Create: `internal/cli/render.go`
- Test: `internal/cli/render_test.go` (unit tests for the helpers only — full command coverage is Task 3)

**Interfaces:**
- Consumes: `render.Render/Unresolved/Syntax*`, `getUnlockedVault`, `getGlobalFlags`, `getFormatter`, `validName` (not needed — matcher handles names), `exitWithError`.
- Produces:
  - `func formatUnresolved(unresolved []render.Unresolved) string` — `NAME ({{...}})` / `NAME ($...)`, inner echo capped at 32 bytes + `… (N bytes total)`.
  - `func writeRenderedOutput(path string, data []byte) error` — open(0600) → `f.Chmod(0600)` → single write → close.
  - cobra command `render` with local flags `--in`, `--out`, `--strict`; `--tag` inherited from the root persistent flag.

- [ ] **Step 1: Write failing tests**

`internal/cli/render_test.go`:

```go
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/render"
)

func TestFormatUnresolved(t *testing.T) {
	got := formatUnresolved([]render.Unresolved{
		{Name: "MISSING", Syntax: render.SyntaxBrace},
		{Name: "HOME", Syntax: render.SyntaxShell},
	})
	want := "MISSING ({{...}}), HOME ($...)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	long := strings.Repeat("x", 50)
	got = formatUnresolved([]render.Unresolved{{Name: long, Syntax: render.SyntaxBrace}})
	if !strings.HasPrefix(got, strings.Repeat("x", 32)+"… (50 bytes total)") {
		t.Fatalf("cap missing: %q", got)
	}
}

func TestWriteRenderedOutputPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.env")
	if err := os.WriteFile(path, []byte("old wider content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeRenderedOutput(path, []byte("secret123")); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", st.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if string(data) != "secret123" {
		t.Fatalf("content = %q", data)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/cli/ -run 'FormatUnresolved|WriteRenderedOutput' -v`
Expected: FAIL — `formatUnresolved undefined`.

- [ ] **Step 3: Implement**

`internal/cli/render.go`:

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/render"
)

const unresolvedEchoCap = 32

func formatUnresolved(unresolved []render.Unresolved) string {
	parts := make([]string, 0, len(unresolved))
	for _, u := range unresolved {
		name := u.Name
		if len(name) > unresolvedEchoCap {
			name = name[:unresolvedEchoCap] + fmt.Sprintf("… (%d bytes total)", len(u.Name))
		}
		tag := "($...)"
		if u.Syntax == render.SyntaxBrace {
			tag = "({{...}})"
		}
		parts = append(parts, name+" "+tag)
	}
	return strings.Join(parts, ", ")
}

func writeRenderedOutput(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod output file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write output file: %w", err)
	}
	return f.Close()
}

var renderCmd = &cobra.Command{
	Use:   "render",
	Short: "Render a template file, substituting vault secrets",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, global, env, tags := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		in, _ := cmd.Flags().GetString("in")
		out, _ := cmd.Flags().GetString("out")
		strict, _ := cmd.Flags().GetBool("strict")

		if in == "" || out == "" {
			exitWithError("--in and --out are required")
		}
		if out == "-" {
			exitWithError("--out - is not supported: values must not go to stdout")
		}
		inAbs, err := filepath.Abs(in)
		if err != nil {
			exitWithError(err.Error())
		}
		outAbs, err := filepath.Abs(out)
		if err != nil {
			exitWithError(err.Error())
		}
		if filepath.Clean(inAbs) == filepath.Clean(outAbs) {
			exitWithError("refusing to overwrite the template")
		}
		tmpl, err := os.ReadFile(in)
		if err != nil {
			exitWithError("read template: " + err.Error())
		}

		v, err := getUnlockedVault(cmd, jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		var values map[string][]byte
		if len(tags) > 0 {
			metas, terr := v.GetSecretsByTags(tags)
			if terr != nil {
				exitWithError(terr.Error())
			}
			values = make(map[string][]byte, len(metas))
			for _, m := range metas {
				sec, gerr := v.GetSecret(m.Name)
				if gerr != nil {
					exitWithError(gerr.Error())
				}
				values[m.Name] = sec.Value
			}
		} else {
			values, err = v.GetAllSecrets()
			if err != nil {
				exitWithError(err.Error())
			}
		}

		result, unresolved, subs := render.Render(tmpl, values)
		var report []render.Unresolved
		for _, u := range unresolved {
			if u.Syntax == render.SyntaxBrace || strict {
				report = append(report, u)
			}
		}
		if len(report) > 0 {
			exitWithError("unresolved placeholders: " + formatUnresolved(report))
		}
		if err := writeRenderedOutput(out, result); err != nil {
			exitWithError(err.Error())
		}
		if !quiet && !jsonOut {
			f.Success(fmt.Sprintf("Rendered %d placeholders → %s", subs, out))
		}
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	renderCmd.Flags().String("in", "", "Template input file")
	renderCmd.Flags().String("out", "", "Rendered output file (0600)")
	renderCmd.Flags().Bool("strict", false, "Fail on unresolved $VAR / ${VAR} placeholders too")
	rootCmd.AddCommand(renderCmd)
}
```

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/cli/ -run 'FormatUnresolved|WriteRenderedOutput' -v && make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/render.go internal/cli/render_test.go
git commit -m "feat: psst render command"
```

---

### Task 3: integration tests

**Files:**
- Test: `tests/render_test.go`

**Interfaces:**
- Consumes: the existing `tests/integration_test.go` helpers exactly as they are: `newTestEnv(t)`, `e.run(args...) (stdout, stderr, exitCode string string int)` (env already sets `PSST_PASSWORD=test-password`, `HOME=<dir>`), `e.initVault()`, `e.writeFile(name, content)`. Errors from `exitWithError` land on **stderr** (prefixed `✗`). Read the file first; reuse, do not duplicate.

- [ ] **Step 1: Write the tests**

```go
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func (e *testEnv) setSecret(t *testing.T, name, value string, extraArgs ...string) {
	t.Helper()
	args := append([]string{"set", name, "--stdin"}, extraArgs...)
	cmd := exec.Command(e.binary, args...)
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte(value + "\n"))
		stdin.Close()
	}()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("set %s failed: %s", name, out)
	}
}

func TestRenderHappyPath(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.setSecret(t, "DB_PASS", "test-password")

	e.writeFile("deploy.tpl", "API={{API_KEY}}\nPW=$DB_PASS\nBRACED=${API_KEY}\nHOME=$HOME\n")
	stdout, _, code := e.run("render", "--in", "deploy.tpl", "--out", "deploy.env")
	if code != 0 {
		t.Fatalf("render failed: %s", stdout)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "deploy.env"))
	if err != nil {
		t.Fatal(err)
	}
	want := "API=secret123\nPW=test-password\nBRACED=secret123\nHOME=$HOME\n"
	if string(data) != want {
		t.Fatalf("content = %q, want %q", data, want)
	}
	if !strings.Contains(stdout, "Rendered 3 placeholders") {
		t.Fatalf("summary missing N: %s", stdout)
	}
	if strings.Contains(stdout, "secret123") || strings.Contains(stdout, "test-password") {
		t.Fatal("value leaked to stdout")
	}
	st, _ := os.Stat(filepath.Join(e.dir, "deploy.env"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
}

func TestRenderPermsRepair(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}}")
	if err := os.WriteFile(filepath.Join(e.dir, "wide.env"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := e.run("render", "--in", "tpl", "--out", "wide.env"); code != 0 {
		t.Fatal("render failed")
	}
	st, _ := os.Stat(filepath.Join(e.dir, "wide.env"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600 (chmod repair)", st.Mode().Perm())
	}
}

func TestRenderUnresolvedBrace(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}} and {{MISSING}}")
	_, stderr, code := e.run("render", "--in", "tpl", "--out", "nope.env")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "MISSING") {
		t.Fatalf("missing name in error: %s", stderr)
	}
	if strings.Contains(stderr, "secret123") {
		t.Fatal("value leaked in error output")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "nope.env")); !os.IsNotExist(err) {
		t.Fatal("output file must not be created on unresolved")
	}
}

func TestRenderStrict(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}} $HOME")
	if _, _, code := e.run("render", "--in", "tpl", "--out", "o.env", "--strict"); code != 1 {
		t.Fatalf("strict code = %d, want 1", code)
	}
	e.writeFile("tpl2", "{{API_KEY}}")
	if _, _, code := e.run("render", "--in", "tpl2", "--out", "o2.env", "--strict"); code != 0 {
		t.Fatalf("strict happy code = %d", code)
	}
}

func TestRenderTagFilter(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123", "--tag", "prod")
	e.setSecret(t, "DB_PASS", "test-password", "--tag", "dev")

	e.writeFile("tpl1", "{{API_KEY}} {{DB_PASS}}")
	e.writeFile("tpl2", "{{API_KEY}}")

	_, stderr, code := e.run("render", "--in", "tpl1", "--out", "tag1.env", "--tag", "prod")
	if code != 1 {
		t.Fatalf("code = %d, want 1 (DB_PASS outside tag set)", code)
	}
	if !strings.Contains(stderr, "DB_PASS") {
		t.Fatalf("error must name DB_PASS: %s", stderr)
	}
	if _, _, code := e.run("render", "--in", "tpl2", "--out", "tag2.env", "--tag", "prod"); code != 0 {
		t.Fatalf("tag render code = %d", code)
	}
	data, _ := os.ReadFile(filepath.Join(e.dir, "tag2.env"))
	if string(data) != "secret123" {
		t.Fatalf("content = %q", data)
	}
}

func TestRenderRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}}")
	if _, _, code := e.run("render", "--in", "tpl", "--out", "tpl"); code != 1 {
		t.Fatalf("out==in code = %d", code)
	}
	if _, stderr, code := e.run("render", "--in", "tpl", "--out", "-"); code != 1 {
		t.Fatalf("out - code = %d", code)
	} else if !strings.Contains(stderr, "stdout") {
		t.Fatalf("out - message: %s", stderr)
	}
}

func TestRenderGitVault(t *testing.T) {
	e := newTestEnv(t)
	if _, _, code := e.run("init", "--storage", "git"); code != 0 {
		t.Fatal("git init failed")
	}
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}} $API_KEY")
	if _, _, code := e.run("render", "--in", "tpl", "--out", "g.env", "--storage", "git"); code != 0 {
		t.Fatalf("git render failed")
	}
	data, _ := os.ReadFile(filepath.Join(e.dir, "g.env"))
	if string(data) != "secret123 secret123" {
		t.Fatalf("content = %q", data)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `make test`
Expected: PASS (all packages; render integration adds a few seconds).

- [ ] **Step 3: Commit**

```bash
git add tests/render_test.go
git commit -m "test: render integration tests"
```

---

### Task 4: documentation

**Files:**
- Modify: `docs/rules/security.md` (egress inventory line — present tense for render)
- Modify: `docs/rules/architecture.md` (render/ leaf row + dependency)
- Modify: `README.md`, `docs/ru/README.md` (render section + recipes + the two mandatory warnings from spec §4.3)

**Interfaces:** Produces documentation only.

- [ ] **Step 1: Edit `docs/rules/security.md`**

Find the egress-inventory sentence in "What NOT To Do" containing `psst render (future phase) adds a 0600 file channel` and update it to present tense:

```
Plaintext egress inventory: the child process environment (runner), the 0600 file
produced by `psst render`, the web UI reveal (phase 2), and the explicit
operator-initiated exceptions `psst get` / `psst export`.
```

- [ ] **Step 2: Edit `docs/rules/architecture.md`**

In the Layers diagram add after `runner/`:

```
│  render/                        │  Template substitution — single-pass matcher (leaf, no internal deps)
```

In Dependency Rules append:

```
8. **Allowed:** `cli → render`. `render/` is a pure leaf package (stdlib only) and must not import any other internal package.
```

- [ ] **Step 3: Edit `README.md` + `docs/ru/README.md`**

Add after the Web UI section (English README):

```markdown
### Render templates

```bash
psst render --in deploy.env.tpl --out deploy.env           # output is always 0600
psst render --in config.yaml.tpl --out config.yaml --tag prod
psst render --in app.ini.tpl --out app.ini --strict
```

- `{{KEY}}` — must resolve; unresolved names fail the command (fail-closed: a literal
  `{{KEY}}` never ships). Note: templates mixing another `{{ }}` templating system
  (Helm, Go templates) cannot be rendered — every `{{...}}` span must resolve.
- `$KEY` / `${KEY}` — replaced when the secret exists, left as-is otherwise.
- `--strict` — unresolved `$` placeholders fail too.
- Rendered files are plaintext secrets: add them to `.gitignore` (only `.env`/`.env.*`
  are ignored by default); `psst scan` catches tracked leaks.

Protocol-independent recipes (no proxy needed):

```bash
psst SSHPASS -- sshpass -e ssh user@host            # env injection
psst render --in deploy.env.tpl --out deploy.env    # file generation
docker --env-file <(psst export) run ...            # container env
```
```

Mirror the same section in Russian in `docs/ru/README.md` (Відображение шаблонов → «Рендер шаблонов»: те же пункты, включая оба предупреждения).

- [ ] **Step 4: Run tests + commit**

Run: `make test` (docs-only sanity). Commit:

```bash
git add docs/rules/security.md docs/rules/architecture.md README.md docs/ru/README.md
git commit -m "docs: psst render documentation and recipes"
```

---

## Final verification (after all tasks)

- [ ] `make test` green; `go vet ./...` clean; `gofmt` clean.
- [ ] Manual smoke in the worktree: init vault → set 2 secrets → render a mixed template → check output content + `ls -l` shows 0600 → run with `{{MISSING}}` → error, no file.
- [ ] Spec §6 checklist fully covered by Tasks 1-3 (including the two folded control-round nits: 32-byte cap asserted in integration error output where names are long — optional; `${VAR:-x}` under `--strict` pinned by Task 1's `${VAR:-x}` boundary case + strict decision path).
- [ ] Final diff review by a fresh subagent, then `git merge --no-ff feat/render` into main under maintainer review.
