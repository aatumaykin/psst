package cli

import (
	"bufio"
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
	Run: func(cmd *cobra.Command, args []string) {
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

		files, err := getScanFiles(staged, scanPath)
		if err != nil {
			exitWithError(err.Error())
		}

		var results []output.ScanMatch
		for _, file := range files {
			matches := scanFile(file, secrets)
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
		filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				files = append(files, path)
			}
			return nil
		})
		return files, nil
	}

	if staged {
		out, err := exec.Command("git", "diff", "--cached", "--name-only").Output()
		if err != nil {
			return nil, err
		}
		return splitLines(string(out)), nil
	}

	out, err := exec.Command("git", "ls-files").Output()
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

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var results []output.ScanMatch
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
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
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func init() {
	scanCmd.Flags().Bool("staged", false, "Scan only staged files")
	scanCmd.Flags().String("path", "", "Scan specific directory")
	rootCmd.AddCommand(scanCmd)
}
