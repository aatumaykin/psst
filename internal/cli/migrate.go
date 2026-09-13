package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

func runMigrateKDF(cmd *cobra.Command) error {
	return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
		if migrateErr := v.MigrateKDF(cmd.Context()); migrateErr != nil {
			return exitWithError(fmt.Sprintf("Migration failed: %v", migrateErr))
		}
		f.Success(fmt.Sprintf("Vault migrated to KDF version %d", crypto.CurrentKDFVersion))
		return nil
	})
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate vault to latest KDF version or another storage backend",
	RunE:  func(cmd *cobra.Command, _ []string) error { return runMigrateKDF(cmd) },
}

var migrateKDFCmd = &cobra.Command{
	Use:   "kdf",
	Short: "Migrate vault to latest KDF version",
	RunE:  func(cmd *cobra.Command, _ []string) error { return runMigrateKDF(cmd) },
}

var migrateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Migrate vault to another storage backend",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		f := getFormatter(cfg.JSON, cfg.Quiet)
		ctx := cmd.Context()
		to, _ := cmd.Flags().GetString("to")
		remote, _ := cmd.Flags().GetString("remote")
		allowInsecure, _ := cmd.Flags().GetBool("allow-insecure-remote")

		if to != "git" {
			return exitWithError("only --to git is supported")
		}

		envDir, err := vault.FindVaultDir(cfg.Global, cfg.Env)
		if err != nil {
			return exitWithError(err.Error())
		}

		storage, err := ResolveStorage(cfg.Storage, envDir)
		if err != nil {
			return exitWithError(err.Error())
		}
		if storage != "sqlite" {
			return exitWithError("source vault must be sqlite")
		}

		srcStore, err := store.NewSQLite(vault.SQLitePath(envDir))
		if err != nil {
			return exitWithError(err.Error())
		}
		kdfVersion, _ := srcStore.GetMeta(ctx, "kdf_version")
		_ = srcStore.Close()
		if kdfVersion != strconv.Itoa(crypto.CurrentKDFVersion) {
			return exitWithError("vault uses legacy KDF (v1); run `psst migrate kdf` first")
		}

		if remote == "" {
			return exitWithError("--remote is required for storage migration")
		}
		if err := ValidateRemoteScheme(remote, allowInsecure); err != nil {
			return exitWithError(err.Error())
		}

		envPassword := os.Getenv("PSST_PASSWORD")

		v, err := getUnlockedVault(ctx, cfg.JSON, cfg.Quiet, cfg)
		if err != nil {
			return err
		}

		metas, err := v.ListSecrets(ctx)
		if err != nil {
			_ = v.Close()
			return exitWithError(err.Error())
		}
		var offenders []string
		tagByName := make(map[string][]string, len(metas))
		for _, m := range metas {
			tagByName[m.Name] = m.Tags
			bad := len(m.Tags) > 1
			for _, t := range m.Tags {
				if t != "" && !store.ValidTag.MatchString(t) {
					bad = true
				}
			}
			if bad {
				offenders = append(offenders, fmt.Sprintf("%s (tag %q)", m.Name, strings.Join(m.Tags, ", ")))
			}
		}
		if len(offenders) > 0 {
			_ = v.Close()
			sort.Strings(offenders)
			return exitWithError("git vault supports a single valid tag per secret; re-tag these secrets first: " +
				strings.Join(offenders, ", "))
		}

		values, err := v.GetAllSecrets(ctx)
		if err != nil {
			_ = v.Close()
			return exitWithError(err.Error())
		}
		if err := v.Close(); err != nil {
			return exitWithError(err.Error())
		}

		repoPath := filepath.Join(envDir, "repo")
		if statExists(repoPath) {
			return exitWithError("git vault already exists at " + repoPath)
		}

		opts := gitStoreOptions(envDir)
		opts.Remote = remote
		opts.AllowInsecureRemote = allowInsecure

		gs, err := store.CloneGitVault(remote, repoPath, opts)
		if err != nil {
			return exitWithError(err.Error())
		}
		if emptyErr := ensureRemoteEmpty(repoPath); emptyErr != nil {
			_ = gs.Close()
			_ = os.RemoveAll(repoPath)
			return exitWithError(emptyErr.Error())
		}
		if err := gs.InitSchema(); err != nil {
			return exitWithError(err.Error())
		}

		enc := crypto.NewAESGCM()
		var v2kp keyring.KeyProvider = keyring.NewPasswordProvider(enc, true)
		if envPassword != "" {
			v2kp = keyring.NewFixedProvider(envPassword)
		}
		v2 := vault.New(enc, v2kp, gs)
		if err := v2.Unlock(ctx); err != nil {
			return exitWithError(fmt.Sprintf("unlock git vault: %v", err))
		}
		if err := v2.Batch(func() error {
			for name, value := range values {
				if err := v2.SetSecret(ctx, name, value, tagByName[name]); err != nil {
					return fmt.Errorf("set %s: %w", name, err)
				}
			}
			return nil
		}); err != nil {
			return exitWithError(fmt.Sprintf("Migration failed: %v", err))
		}
		if err := gs.Sync(); err != nil {
			return exitWithError(err.Error())
		}

		vcfg, err := LoadVaultConfig(envDir)
		if err != nil {
			return exitWithError(err.Error())
		}
		vcfg.Storage = "git"
		vcfg.Remote = remote
		if err := SaveVaultConfig(envDir, *vcfg); err != nil {
			return exitWithError(err.Error())
		}

		_ = v2.Close()

		f.Success(fmt.Sprintf("Migrated %d secret(s) to git vault at %s", len(values), repoPath))
		return nil
	},
}

func ensureRemoteEmpty(repoPath string) error {
	if statExists(filepath.Join(repoPath, "psst.yaml")) {
		return errors.New("remote is not an empty vault; init a fresh remote or " +
			"clone it with 'psst init --storage git --remote ...'")
	}
	return nil
}

//nolint:gochecknoinits // cobra command registration
func init() {
	migrateStorageCmd.Flags().String("to", "", "Target storage backend (git)")
	migrateStorageCmd.Flags().String("remote", "", "Git remote URL")
	migrateStorageCmd.Flags().Bool("allow-insecure-remote", false, "Allow http:// git remote")
	migrateCmd.AddCommand(migrateKDFCmd)
	migrateCmd.AddCommand(migrateStorageCmd)
	rootCmd.AddCommand(migrateCmd)
}
