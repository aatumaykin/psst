package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan files for leaked secrets",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		staged, _ := cmd.Flags().GetBool("staged")
		scanPath, _ := cmd.Flags().GetString("path")

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		secrets, err := v.GetAllSecrets()
		if err != nil {
			exitWithError(err.Error())
		}

		if len(secrets) == 0 {
			f.Success("No secrets in vault to scan for.")
			return
		}

		strSecrets := make(map[string]string, len(secrets))
		for k, v := range secrets {
			strSecrets[k] = string(v)
		}

		files, err := getScanFiles(staged, scanPath)
		if err != nil {
			exitWithError(err.Error())
		}

		var results []output.ScanMatch
		for _, file := range files {
			matches := scanFile(file, strSecrets)
			results = append(results, matches...)
		}

		f.ScanResults(results)
		if len(results) > 0 {
			os.Exit(1)
		}
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

func scanFile(path string, secrets map[string]string) []output.ScanMatch {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > 1024*1024 {
		return nil
	}

	if isBinaryExtension(path) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	data = bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))

	var results []output.ScanMatch
	lineNum := 0
	for _, line := range splitLines(string(data)) {
		lineNum++
		line = strings.TrimRight(line, "\r")
		if strings.ContainsRune(line, 0) {
			return nil
		}
		for name, value := range secrets {
			if len(value) >= 4 && strings.Contains(line, value) {
				results = append(results, output.ScanMatch{
					File:       path,
					Line:       lineNum,
					SecretName: name,
				})
			}
		}
	}
	return results
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
