package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/render"
)

const (
	unresolvedEchoCap = 32
	renderOutPerm     = 0o600
)

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
	if runtime.GOOS != goosWindows {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Refusing to write to symlink: " + path)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, renderOutPerm)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	if err = f.Chmod(renderOutPerm); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod output file: %w", err)
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write output file: %w", err)
	}
	return f.Close()
}

var renderCmd = &cobra.Command{
	Use:   "render",
	Short: "Render a template file, substituting vault secrets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		f := getFormatter(cfg.JSON, cfg.Quiet)
		ctx := cmd.Context()
		in, _ := cmd.Flags().GetString("in")
		out, _ := cmd.Flags().GetString("out")
		strict, _ := cmd.Flags().GetBool("strict")

		if in == "" || out == "" {
			return exitWithError("--in and --out are required")
		}
		if out == "-" {
			return exitWithError("--out - is not supported: values must not go to stdout")
		}
		inAbs, err := filepath.Abs(in)
		if err != nil {
			return exitWithError(err.Error())
		}
		outAbs, err := filepath.Abs(out)
		if err != nil {
			return exitWithError(err.Error())
		}
		if filepath.Clean(inAbs) == filepath.Clean(outAbs) {
			return exitWithError("refusing to overwrite the template")
		}
		tmpl, err := os.ReadFile(in)
		if err != nil {
			return exitWithError("read template: " + err.Error())
		}

		v, err := getUnlockedVault(ctx, cfg.JSON, cfg.Quiet, cfg)
		if err != nil {
			return err
		}
		defer v.Close()

		var values map[string][]byte
		if len(cfg.Tags) > 0 {
			metas, terr := v.GetSecretsByTags(ctx, cfg.Tags)
			if terr != nil {
				return exitWithError(terr.Error())
			}
			values = make(map[string][]byte, len(metas))
			for _, m := range metas {
				sec, gerr := v.GetSecret(ctx, m.Name)
				if gerr != nil {
					return exitWithError(gerr.Error())
				}
				values[m.Name] = sec.Value
			}
		} else {
			values, err = v.GetAllSecrets(ctx)
			if err != nil {
				return exitWithError(err.Error())
			}
		}
		defer zeroSecretMap(values)

		result, unresolved, subs := render.Render(tmpl, values)
		var report []render.Unresolved
		for _, u := range unresolved {
			if u.Syntax == render.SyntaxBrace || strict {
				report = append(report, u)
			}
		}
		if len(report) > 0 {
			return exitWithError("unresolved placeholders: " + formatUnresolved(report))
		}
		if err = writeRenderedOutput(out, result); err != nil {
			return exitWithError(err.Error())
		}
		f.Success(fmt.Sprintf("Rendered %d placeholders → %s", subs, out))
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	renderCmd.Flags().String("in", "", "Template input file")
	renderCmd.Flags().String("out", "", "Rendered output file (0600)")
	renderCmd.Flags().Bool("strict", false, "Fail on unresolved $VAR / ${VAR} placeholders too")
	rootCmd.AddCommand(renderCmd)
}
