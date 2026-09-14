package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new vault",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		f := getFormatter(cfg.JSON, cfg.Quiet)
		remote, _ := cmd.Flags().GetString("remote")
		allowInsecure, _ := cmd.Flags().GetBool("allow-insecure-remote")

		if cfg.Storage == storageGit {
			return initGitVault(f, cfg, remote, allowInsecure)
		}

		vaultPath, err := resolveVaultPath(cfg)
		if err != nil {
			return exitWithError(err.Error())
		}

		keychainAvailable := keyring.IsKeychainAvailable()
		envPasswordSet := keyring.IsEnvPasswordSet()

		if !keychainAvailable && !envPasswordSet {
			return exitWithError(
				"OS keychain unavailable. Set PSST_PASSWORD before running init:\n" +
					"  export PSST_PASSWORD=\"your-password\"\n" +
					"  psst init")
		}

		enc := crypto.NewAESGCM()
		kp := keyring.NewProvider(enc)

		opts := vault.InitOptions{
			Global: cfg.Global,
			Env:    cfg.Env,
		}

		if initErr := vault.InitVault(cmd.Context(), vaultPath, enc, kp, opts); initErr != nil {
			return exitWithError(initErr.Error())
		}

		f.Success("Vault created at " + vaultPath)

		if !keychainAvailable {
			f.Warning("Using PSST_PASSWORD (OS keychain unavailable)")
			f.Bullet("Set PSST_PASSWORD before each use:")
			f.Bullet(`export PSST_PASSWORD="your-password"`)
			f.Bullet("Note: PSST_PASSWORD is visible to other users via /proc on shared systems")
		}
		return nil
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

func initGitVault(f *output.Formatter, cfg globalConfig, remote string, allowInsecure bool) error {
	envDir, err := vault.FindVaultDir(cfg.Global, cfg.Env)
	if err != nil {
		return exitWithError(err.Error())
	}

	if !keyring.IsEnvPasswordSet() && !term.IsTerminal(int(os.Stdin.Fd())) {
		return exitWithError(
			"Set PSST_PASSWORD before running init:\n" +
				"  export PSST_PASSWORD=\"your-password\"\n" +
				"  psst init --storage git")
	}

	repoPath := filepath.Join(envDir, "repo")
	if statExists(repoPath) {
		return exitWithError("git vault already exists at " + repoPath)
	}

	opts := gitStoreOptions(envDir)
	opts.Remote = remote
	opts.AllowInsecureRemote = allowInsecure

	if remote != "" {
		if err = ValidateRemoteScheme(remote, allowInsecure); err != nil {
			return exitWithError(err.Error())
		}
		gs, cloneErr := store.CloneGitVault(remote, repoPath, opts)
		if cloneErr != nil {
			return exitWithError(cloneErr.Error())
		}
		if schemaErr := gs.InitSchema(); schemaErr != nil {
			return exitWithError(schemaErr.Error())
		}
	} else {
		gs, newErr := store.NewGitStore(repoPath, opts)
		if newErr != nil {
			return exitWithError(newErr.Error())
		}
		if schemaErr := gs.InitSchema(); schemaErr != nil {
			return exitWithError(schemaErr.Error())
		}
	}

	vcfg, err := LoadVaultConfig(envDir)
	if err != nil {
		return exitWithError(err.Error())
	}
	vcfg.Storage = storageGit
	vcfg.Remote = remote
	if err = SaveVaultConfig(envDir, *vcfg); err != nil {
		return exitWithError(err.Error())
	}

	msg := "Git vault created at " + repoPath
	if remote != "" {
		msg += " (remote: " + remote + ")"
	}
	f.Success(msg)

	if !keyring.IsEnvPasswordSet() {
		f.Warning("Set PSST_PASSWORD before each use")
	}
	return nil
}

//nolint:gochecknoinits // cobra command registration
func init() {
	initCmd.Flags().String("remote", "", "Git remote URL for git storage")
	initCmd.Flags().Bool("allow-insecure-remote", false, "Allow http:// git remote")
	rootCmd.AddCommand(initCmd)
}
