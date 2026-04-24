package cli

import (
	"os"
	"strings"
)

func parseGlobalFlagsFromArgs(args []string) (jsonOut, quiet, global bool, env string, tags []string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--quiet", "-q":
			quiet = true
		case "--global", "-g":
			global = true
		case "--env":
			i++
			if i < len(args) {
				env = args[i]
			}
		case "--tag":
			i++
			if i < len(args) {
				tags = append(tags, args[i])
			}
		}
	}
	if os.Getenv("PSST_GLOBAL") == "1" {
		global = true
	}
	if env == "" {
		env = os.Getenv("PSST_ENV")
	}
	return
}

func filterSecretNames(args []string, jsonOut, quiet, global bool, env string, tags []string) []string {
	skip := map[string]bool{"--json": true, "--quiet": true, "-q": true, "--global": true, "-g": true, "--no-mask": true}
	var names []string
	for _, a := range args {
		if skip[a] || a == "--env" || a == "--tag" || a == env {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	return names
}

func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
