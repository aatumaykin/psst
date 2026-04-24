package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aatumaykin/psst/internal/vault"
)

type ScanMatch struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	SecretName string `json:"secret_name"`
}

type Formatter struct {
	jsonMode bool
	quiet    bool
}

func NewFormatter(jsonMode, quiet bool) *Formatter {
	return &Formatter{jsonMode: jsonMode, quiet: quiet}
}

func (f *Formatter) Success(msg string) {
	if f.jsonMode {
		f.printJSON(map[string]string{"status": "success", "message": msg})
		return
	}
	if f.quiet {
		return
	}
	fmt.Fprintf(os.Stdout, "✓ %s\n", msg)
}

func (f *Formatter) Error(msg string) {
	fmt.Fprintf(os.Stderr, "✗ %s\n", msg)
}

func (f *Formatter) Warning(msg string) {
	if f.quiet {
		return
	}
	fmt.Fprintf(os.Stdout, "⚠ %s\n", msg)
}

func (f *Formatter) Bullet(msg string) {
	if f.quiet {
		return
	}
	fmt.Fprintf(os.Stdout, "  • %s\n", msg)
}

func (f *Formatter) SecretList(secrets []vault.SecretMeta) {
	if f.jsonMode {
		f.printJSON(secrets)
		return
	}
	for _, s := range secrets {
		if len(s.Tags) > 0 {
			fmt.Fprintf(os.Stdout, "  %s [%s]\n", s.Name, strings.Join(s.Tags, ", "))
		} else {
			fmt.Fprintf(os.Stdout, "  %s\n", s.Name)
		}
	}
}

func (f *Formatter) SecretValue(name, value string) {
	if f.jsonMode {
		f.printJSON(map[string]string{name: value})
		return
	}
	if f.quiet {
		fmt.Fprintln(os.Stdout, value)
		return
	}
	fmt.Fprintf(os.Stdout, "%s=%s\n", name, value)
}

func (f *Formatter) HistoryEntries(name string, entries []vault.SecretHistoryEntry) {
	if f.jsonMode {
		f.printJSON(entries)
		return
	}
	fmt.Fprintf(os.Stdout, "\nHistory for %s:\n\n", name)
	fmt.Fprintf(os.Stdout, "  ● current (active)\n")
	for _, e := range entries {
		fmt.Fprintf(os.Stdout, "  ● v%d  %s\n", e.Version, e.ArchivedAt.Format("01/02/2006 15:04"))
	}
	fmt.Fprintf(os.Stdout, "\n  %d previous version(s)\n", len(entries))
	fmt.Fprintf(os.Stdout, "  Rollback: psst rollback %s --to <version>\n", name)
}

func (f *Formatter) ScanResults(results []ScanMatch) {
	if len(results) == 0 {
		f.Success("No secrets found in files.")
		return
	}
	if f.jsonMode {
		f.printJSON(results)
		return
	}
	fmt.Fprintf(os.Stderr, "✗ Secrets found in files:\n\n")
	for _, r := range results {
		fmt.Fprintf(os.Stderr, "  %s:%d\n    Contains: %s\n\n", r.File, r.Line, r.SecretName)
	}
	fmt.Fprintf(os.Stderr, "Found %d secret(s) in %d file(s)\n", len(results), countUniqueFiles(results))
}

func (f *Formatter) EnvList(secrets map[string]string) {
	if f.jsonMode {
		f.printJSON(secrets)
		return
	}
	for name, value := range secrets {
		fmt.Fprintf(os.Stdout, "%s=%s\n", name, quoteValue(value))
	}
}

func (f *Formatter) EnvListWriter(secrets map[string]string, w io.Writer) {
	for name, value := range secrets {
		fmt.Fprintf(w, "%s=%s\n", name, quoteValue(value))
	}
}

func (f *Formatter) EnvironmentList(envs []string) {
	if f.jsonMode {
		f.printJSON(envs)
		return
	}
	if len(envs) == 0 {
		fmt.Fprintln(os.Stdout, "No environments found.")
		return
	}
	for _, e := range envs {
		fmt.Fprintf(os.Stdout, "  %s\n", e)
	}
}

func (f *Formatter) Print(msg string) {
	if !f.quiet {
		fmt.Fprintln(os.Stdout, msg)
	}
}

func (f *Formatter) IsJSON() bool {
	return f.jsonMode
}

func (f *Formatter) IsQuiet() bool {
	return f.quiet
}

func (f *Formatter) printJSON(data any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encoding error: %v\n", err)
	}
}

func quoteValue(v string) string {
	if strings.ContainsAny(v, " \t\n\r\"'") {
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
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
