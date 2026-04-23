package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import secrets from .env file, stdin, or environment",
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		useStdin, _ := cmd.Flags().GetBool("stdin")
		fromEnv, _ := cmd.Flags().GetBool("from-env")

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		var entries map[string]string

		switch {
		case fromEnv:
			entries = readFromEnv()
		case useStdin:
			entries, err = parseEnvFromReader(os.Stdin)
			if err != nil {
				exitWithError(err.Error())
			}
		default:
			if len(args) > 0 {
				file, err := os.Open(args[0])
				if err != nil {
					exitWithError(fmt.Sprintf("Cannot open file: %v", err))
				}
				defer file.Close()
				entries, err = parseEnvFromReader(file)
				if err != nil {
					exitWithError(err.Error())
				}
			} else {
				exitWithError("Specify a file, --stdin, or --from-env")
				return
			}
		}

		count := 0
		for name, value := range entries {
			if !validName.MatchString(name) {
				if !quiet {
					fmt.Fprintf(os.Stderr, "Skipping invalid name: %s\n", name)
				}
				continue
			}
			if err := v.SetSecret(name, value, nil); err != nil {
				exitWithError(fmt.Sprintf("Failed to set %s: %v", name, err))
			}
			count++
		}

		f.Success(fmt.Sprintf("Imported %d secret(s)", count))
	},
}

func parseEnvFromReader(file *os.File) (map[string]string, error) {
	entries := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := parseEnvLine(line)
		if !ok {
			continue
		}
		entries[name] = value
	}
	return entries, scanner.Err()
}

func parseEnvLine(line string) (name, value string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	name = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	value = strings.TrimPrefix(value, `"`)
	value = strings.TrimSuffix(value, `"`)
	value = strings.TrimPrefix(value, `'`)
	value = strings.TrimSuffix(value, `'`)
	return name, value, true
}

func readFromEnv() map[string]string {
	entries := make(map[string]string)
	for _, e := range os.Environ() {
		idx := strings.Index(e, "=")
		if idx < 0 {
			continue
		}
		name := e[:idx]
		value := e[idx+1:]
		if validName.MatchString(name) {
			entries[name] = value
		}
	}
	return entries
}

func init() {
	importCmd.Flags().Bool("stdin", false, "Read from stdin")
	importCmd.Flags().Bool("from-env", false, "Import from environment variables")
	rootCmd.AddCommand(importCmd)
}
