package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan files for leaked secrets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		staged, _ := cmd.Flags().GetBool("staged")
		scanPath, _ := cmd.Flags().GetString("path")

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			secrets, err := v.GetAllSecrets(cmd.Context())
			if err != nil {
				return exitWithError(err.Error())
			}

			if len(secrets) == 0 {
				f.Success("No secrets in vault to scan for.")
				return nil
			}

			byteSecrets := make(map[string][]byte, len(secrets))
			maps.Copy(byteSecrets, secrets)
			defer zeroSecretMap(byteSecrets)

			files, err := getScanFiles(staged, scanPath)
			if err != nil {
				return exitWithError(err.Error())
			}

			var results []output.ScanMatch
			var allWarnings []string
			for _, file := range files {
				matches, warns := scanFile(file, byteSecrets)
				results = append(results, matches...)
				allWarnings = append(allWarnings, warns...)
			}

			f.ScanResults(results)
			for _, w := range allWarnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
			}
			if len(results) > 0 {
				return &exitError{code: 1}
			}
			return nil
		})
	},
}

func getScanFiles(staged bool, scanPath string) ([]string, error) {
	if scanPath != "" {
		var files []string
		err := filepath.Walk(scanPath, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr == nil && !info.IsDir() {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return files, nil
	}

	if _, lookupErr := exec.LookPath("git"); lookupErr != nil {
		return nil, errors.New("git not found: install git or use --path flag")
	}

	if staged {
		out, err := exec.CommandContext(
			context.Background(), "git", "diff", "--cached", "--name-only",
		).Output()
		if err != nil {
			return nil, err
		}
		return splitLines(string(out)), nil
	}

	out, err := exec.CommandContext(
		context.Background(), "git", "ls-files",
	).Output()
	if err != nil {
		return nil, err
	}
	return splitLines(string(out)), nil
}

func scanFile(path string, secrets map[string][]byte) ([]output.ScanMatch, []string) {
	var warnings []string

	info, err := os.Stat(path)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("cannot stat %s: %v", path, err))
		return nil, warnings
	}
	if info.IsDir() || info.Size() > 1024*1024 {
		return nil, warnings
	}

	if isBinaryExtension(path) {
		return nil, warnings
	}

	data, err := os.ReadFile(path)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("cannot read %s: %v", path, err))
		return nil, warnings
	}

	data = bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))

	var results []output.ScanMatch
	lineNum := 0
	for _, line := range splitLines(string(data)) {
		lineNum++
		line = strings.TrimRight(line, "\r")
		if strings.ContainsRune(line, 0) {
			return nil, warnings
		}
		lineData := []byte(line)
		for name, value := range secrets {
			if len(value) >= 4 && bytes.Contains(lineData, value) {
				results = append(results, output.ScanMatch{
					File:       path,
					Line:       lineNum,
					SecretName: name,
				})
			}
		}
	}
	return results, warnings
}

func isBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".pdf": true,
		".zip": true, ".tar": true, ".gz": true, ".exe": true, ".dll": true,
		".so": true, ".o": true, ".a": true, ".woff": true, ".woff2": true,
		".ttf": true, ".eot": true, ".ico": true, ".mp3": true, ".mp4": true,
		".wav": true, ".avi": true, ".mov": true, ".db": true, ".sqlite": true,
	}
	return binaryExts[ext]
}

func splitLines(s string) []string {
	var result []string
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

//nolint:gochecknoinits // cobra command registration
func init() {
	scanCmd.Flags().Bool("staged", false, "Scan only staged files")
	scanCmd.Flags().String("path", "", "Scan specific directory")
	rootCmd.AddCommand(scanCmd)
}
