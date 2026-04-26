package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aatumaykin/psst/internal/version"
)

type ScanMatch struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	SecretName string `json:"secret_name"`
}

type SecretItem struct {
	Name      string    `json:"name"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type HistoryItem struct {
	Version    int       `json:"version"`
	Tags       []string  `json:"tags"`
	ArchivedAt time.Time `json:"archived_at"`
}

type Formatter struct {
	jsonMode bool
	quiet    bool
	stdout   io.Writer
	stderr   io.Writer
}

func NewFormatter(jsonMode, quiet bool) *Formatter {
	return &Formatter{
		jsonMode: jsonMode,
		quiet:    quiet,
		stdout:   os.Stdout,
		stderr:   os.Stderr,
	}
}

func (f *Formatter) Success(msg string) {
	if f.jsonMode {
		f.PrintJSON(map[string]string{"status": "success", "message": msg})
		return
	}
	if f.quiet {
		return
	}
	fmt.Fprintf(f.stdout, "✓ %s\n", msg)
}

func (f *Formatter) Error(msg string) {
	fmt.Fprintf(f.stderr, "✗ %s\n", msg)
}

func (f *Formatter) Warning(msg string) {
	if f.quiet {
		return
	}
	fmt.Fprintf(f.stdout, "⚠ %s\n", msg)
}

func (f *Formatter) Bullet(msg string) {
	if f.quiet {
		return
	}
	fmt.Fprintf(f.stdout, "  • %s\n", msg)
}

func (f *Formatter) SecretList(secrets []SecretItem) {
	if f.jsonMode {
		f.PrintJSON(secrets)
		return
	}
	for _, s := range secrets {
		if len(s.Tags) > 0 {
			fmt.Fprintf(f.stdout, "  %s [%s]\n", s.Name, strings.Join(s.Tags, ", "))
		} else {
			fmt.Fprintf(f.stdout, "  %s\n", s.Name)
		}
	}
}

func (f *Formatter) SecretValue(name, value string) {
	if f.jsonMode {
		f.PrintJSON(map[string]string{name: value})
		return
	}
	if f.quiet {
		fmt.Fprintln(f.stdout, value)
		return
	}
	fmt.Fprintf(f.stdout, "%s=%s\n", name, value)
}

func (f *Formatter) HistoryEntries(name string, entries []HistoryItem) {
	if f.jsonMode {
		f.PrintJSON(entries)
		return
	}
	fmt.Fprintf(f.stdout, "\nHistory for %s:\n\n", name)
	fmt.Fprintf(f.stdout, "  ● current (active)\n")
	for _, e := range entries {
		fmt.Fprintf(f.stdout, "  ● v%d  %s\n", e.Version, e.ArchivedAt.Format("01/02/2006 15:04"))
	}
	fmt.Fprintf(f.stdout, "\n  %d previous version(s)\n", len(entries))
	fmt.Fprintf(f.stdout, "  Rollback: psst rollback %s --to <version>\n", name)
}

func (f *Formatter) ScanResults(results []ScanMatch) {
	if len(results) == 0 {
		f.Success("No secrets found in files.")
		return
	}
	if f.jsonMode {
		f.PrintJSON(results)
		return
	}
	fmt.Fprintf(f.stderr, "✗ Secrets found in files:\n\n")
	for _, r := range results {
		fmt.Fprintf(f.stderr, "  %s:%d\n    Contains: %s\n\n", r.File, r.Line, r.SecretName)
	}
	fmt.Fprintf(f.stderr, "Found %d secret(s) in %d file(s)\n", len(results), countUniqueFiles(results))
}

func (f *Formatter) EnvList(secrets map[string]string) {
	if f.jsonMode {
		f.PrintJSON(secrets)
		return
	}
	for name, value := range secrets {
		fmt.Fprintf(f.stdout, "%s=%s\n", name, quoteValue(value))
	}
}

func (f *Formatter) EnvListWriter(secrets map[string]string, w io.Writer) {
	for name, value := range secrets {
		fmt.Fprintf(w, "%s=%s\n", name, quoteValue(value))
	}
}

func (f *Formatter) EnvironmentList(envs []string) {
	if f.jsonMode {
		f.PrintJSON(envs)
		return
	}
	if len(envs) == 0 {
		fmt.Fprintln(f.stdout, "No environments found.")
		return
	}
	for _, e := range envs {
		fmt.Fprintf(f.stdout, "  %s\n", e)
	}
}

func (f *Formatter) Print(msg string) {
	if !f.quiet {
		fmt.Fprintln(f.stdout, msg)
	}
}

func (f *Formatter) IsJSON() bool {
	return f.jsonMode
}

func (f *Formatter) IsQuiet() bool {
	return f.quiet
}

func (f *Formatter) VersionInfo() {
	if f.jsonMode {
		f.PrintJSON(version.JSON())
		return
	}
	if f.quiet {
		fmt.Fprintln(f.stdout, version.Version)
		return
	}
	fmt.Fprint(f.stdout, version.String()+"\n")
}

func (f *Formatter) PrintJSON(data any) {
	enc := json.NewEncoder(f.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		fmt.Fprintf(f.stderr, "JSON encoding error: %v\n", err)
	}
}

func quoteValue(v string) string {
	if strings.ContainsAny(v, " \t\n\r\"'") {
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		return `"` + v + `"`
	}
	return v
}

func countUniqueFiles(results []ScanMatch) int {
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.File] = true
	}
	return len(seen)
}
