package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new vault",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		remote, _ := cmd.Flags().GetString("remote")
		allowInsecure, _ := cmd.Flags().GetBool("allow-insecure-remote")

		storage := getStorageFlag(cmd)

		if storage == "git" {
			initGitVault(f, global, env, remote, allowInsecure)
			return
		}

		vaultPath, err := vault.FindVaultPath(global, env)
		if err != nil {
			exitWithError(err.Error())
		}

		keychainAvailable := keyring.IsKeychainAvailable()
		envPasswordSet := keyring.IsEnvPasswordSet()

		if !keychainAvailable && !envPasswordSet {
			exitWithError(
				"OS keychain unavailable. Set PSST_PASSWORD before running init:\n" +
					"  export PSST_PASSWORD=\"your-password\"\n" +
					"  psst init")
		}

		enc, kp := createDependencies()

		opts := vault.InitOptions{
			Global: global,
			Env:    env,
		}

		if initErr := vault.InitVault(vaultPath, enc, kp, opts); initErr != nil {
			exitWithError(initErr.Error())
		}

		f.Success("Vault created at " + vaultPath)

		if !keychainAvailable {
			f.Warning("Using PSST_PASSWORD (OS keychain unavailable)")
			f.Bullet("Set PSST_PASSWORD before each use:")
			f.Bullet(`export PSST_PASSWORD="your-password"`)
			f.Bullet("Note: PSST_PASSWORD is visible to other users via /proc on shared systems")
		}
	},
}

func gitStoreOptions(envDir string) store.GitOptions {
	return store.GitOptions{
		LoadPins: func() *store.Pin {
			cfg, err := LoadVaultConfig(envDir)
			if err != nil || cfg.PinSalt == "" {
				return nil
			}
			return &store.Pin{SaltB64: cfg.PinSalt, Params: cfg.PinKDF}
		},
		SavePins: func(p store.Pin) error {
			cur, err := LoadVaultConfig(envDir)
			if err != nil {
				return err
			}
			cur.PinSalt = p.SaltB64
			cur.HasPin = p.SaltB64 != ""
			cur.PinKDF = p.Params
			return SaveVaultConfig(envDir, *cur)
		},
	}
}

func initGitVault(f *output.Formatter, global bool, env, remote string, allowInsecure bool) {
	envDir, err := vault.FindVaultDir(global, env)
	if err != nil {
		exitWithError(err.Error())
	}

	if !keyring.IsEnvPasswordSet() && !term.IsTerminal(int(os.Stdin.Fd())) {
		exitWithError(
			"Set PSST_PASSWORD before running init:\n" +
				"  export PSST_PASSWORD=\"your-password\"\n" +
				"  psst init --storage git")
	}

	repoPath := filepath.Join(envDir, "repo")
	if statExists(repoPath) {
		exitWithError("git vault already exists at " + repoPath)
	}

	opts := gitStoreOptions(envDir)
	opts.Remote = remote
	opts.AllowInsecureRemote = allowInsecure

	if remote != "" {
		if err := ValidateRemoteScheme(remote, allowInsecure); err != nil {
			exitWithError(err.Error())
		}
		gs, cloneErr := store.CloneGitVault(remote, repoPath, opts)
		if cloneErr != nil {
			exitWithError(cloneErr.Error())
		}
		if schemaErr := gs.InitSchema(); schemaErr != nil {
			exitWithError(schemaErr.Error())
		}
	} else {
		gs, newErr := store.NewGitStore(repoPath, opts)
		if newErr != nil {
			exitWithError(newErr.Error())
		}
		if schemaErr := gs.InitSchema(); schemaErr != nil {
			exitWithError(schemaErr.Error())
		}
	}

	cfg, err := LoadVaultConfig(envDir)
	if err != nil {
		exitWithError(err.Error())
	}
	cfg.Storage = "git"
	cfg.Remote = remote
	if err := SaveVaultConfig(envDir, *cfg); err != nil {
		exitWithError(err.Error())
	}

	msg := "Git vault created at " + repoPath
	if remote != "" {
		msg += " (remote: " + remote + ")"
	}
	f.Success(msg)

	if !keyring.IsEnvPasswordSet() {
		f.Warning("Set PSST_PASSWORD before each use")
	}
}

//nolint:gochecknoinits // cobra command registration
func init() {
	initCmd.Flags().String("remote", "", "Git remote URL for git storage")
	initCmd.Flags().Bool("allow-insecure-remote", false, "Allow http:// git remote")
	rootCmd.AddCommand(initCmd)
}
