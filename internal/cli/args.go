package cli

import (
	"slices"
	"strings"
)

type flagDef struct {
	Name     string
	Short    string
	HasValue bool
}

var globalFlags = []flagDef{
	{Name: "--json"},
	{Name: "--quiet", Short: "-q"},
	{Name: "--global", Short: "-g"},
	{Name: "--env", HasValue: true},
	{Name: "--tag", HasValue: true},
}

func isKnownFlag(arg string) bool {
	for _, f := range globalFlags {
		if arg == f.Name || (f.Short != "" && arg == f.Short) {
			return true
		}
		if f.HasValue && strings.HasPrefix(arg, f.Name+"=") {
			return true
		}
	}
	return false
}

func parseGlobalFlagsFromArgs(args []string) globalConfig {
	cfg := globalConfig{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			cfg.JSON = true
		case "--quiet", "-q":
			cfg.Quiet = true
		case "--global", "-g":
			cfg.Global = true
		case "--env":
			i++
			if i < len(args) {
				cfg.Env = args[i]
			}
		case "--tag":
			i++
			if i < len(args) {
				cfg.Tags = append(cfg.Tags, args[i])
			}
		default:
			if v, found := strings.CutPrefix(args[i], "--env="); found {
				cfg.Env = v
				continue
			}
			if v, found := strings.CutPrefix(args[i], "--tag="); found {
				cfg.Tags = append(cfg.Tags, v)
			}
		}
	}
	resolveEnvOverrides(&cfg)
	return cfg
}

func filterSecretNames(args []string) []string {
	valueArgs := map[int]bool{}
	for i := 0; i < len(args); i++ {
		for _, f := range globalFlags {
			if !f.HasValue {
				continue
			}
			if args[i] == f.Name && i+1 < len(args) {
				valueArgs[i] = true
				valueArgs[i+1] = true
				i++
				break
			}
			if strings.HasPrefix(args[i], f.Name+"=") {
				valueArgs[i] = true
				break
			}
		}
	}

	extraFlags := map[string]bool{"--no-mask": true, "--expand-args": true}

	var names []string
	for i, a := range args {
		if isKnownFlag(a) || extraFlags[a] || valueArgs[i] {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	return names
}

func filterSubcommandNames(names []string) []string {
	subcommands := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		subcommands[cmd.Name()] = true
		for _, alias := range cmd.Aliases {
			subcommands[alias] = true
		}
	}
	filtered := make([]string, 0, len(names))
	for _, name := range names {
		if !subcommands[name] {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

func containsFlag(args []string, flag string) bool {
	return slices.Contains(args, flag)
}
