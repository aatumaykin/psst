package cli

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

func runMigrateKDF(cmd *cobra.Command) {
	jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
	f := getFormatter(jsonOut, quiet)

	v, err := getUnlockedVault(cmd, jsonOut, quiet, global, env)
	if err != nil {
		exitWithError(err.Error())
	}
	defer v.Close()

	if migrateErr := v.MigrateKDF(); migrateErr != nil {
		exitWithError(fmt.Sprintf("Migration failed: %v", migrateErr))
	}

	f.Success(fmt.Sprintf("Vault migrated to KDF version %d", crypto.CurrentKDFVersion))
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate vault to latest KDF version or another storage backend",
	Run:   func(cmd *cobra.Command, _ []string) { runMigrateKDF(cmd) },
}

var migrateKDFCmd = &cobra.Command{
	Use:   "kdf",
	Short: "Migrate vault to latest KDF version",
	Run:   func(cmd *cobra.Command, _ []string) { runMigrateKDF(cmd) },
}

var migrateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Migrate vault to another storage backend",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		to, _ := cmd.Flags().GetString("to")
		remote, _ := cmd.Flags().GetString("remote")
		allowInsecure, _ := cmd.Flags().GetBool("allow-insecure-remote")

		if to != "git" {
			exitWithError("only --to git is supported")
		}

		envDir, err := vault.FindVaultDir(global, env)
		if err != nil {
			exitWithError(err.Error())
		}

		storage, err := ResolveStorage(getStorageFlag(cmd), envDir)
		if err != nil {
			exitWithError(err.Error())
		}
		if storage != "sqlite" {
			exitWithError("source vault must be sqlite")
		}

		srcStore, err := store.NewSQLite(vault.SQLitePath(envDir))
		if err != nil {
			exitWithError(err.Error())
		}
		kdfVersion, _ := srcStore.GetMeta("kdf_version")
		_ = srcStore.Close()
		if kdfVersion != strconv.Itoa(crypto.CurrentKDFVersion) {
			exitWithError("vault uses legacy KDF (v1); run `psst migrate kdf` first")
		}

		if remote == "" {
			exitWithError("--remote is required for storage migration")
		}
		if err := ValidateRemoteScheme(remote, allowInsecure); err != nil {
			exitWithError(err.Error())
		}

		v, err := getUnlockedVault(cmd, jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}

		metas, err := v.ListSecrets()
		if err != nil {
			exitWithError(err.Error())
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
			sort.Strings(offenders)
			exitWithError("git vault supports a single valid tag per secret; re-tag these secrets first: " +
				strings.Join(offenders, ", "))
		}

		values, err := v.GetAllSecrets()
		if err != nil {
			exitWithError(err.Error())
		}
		if err := v.Close(); err != nil {
			exitWithError(err.Error())
		}

		repoPath := filepath.Join(envDir, "repo")
		if statExists(repoPath) {
			exitWithError("git vault already exists at " + repoPath)
		}

		opts := gitStoreOptions(envDir)
		opts.Remote = remote
		opts.AllowInsecureRemote = allowInsecure

		gs, err := store.CloneGitVault(remote, repoPath, opts)
		if err != nil {
			exitWithError(err.Error())
		}
		if err := gs.InitSchema(); err != nil {
			exitWithError(err.Error())
		}

		enc := crypto.NewAESGCM()
		v2 := vault.New(enc, keyring.NewPasswordProvider(enc, true), gs)
		if err := v2.Unlock(); err != nil {
			exitWithError(fmt.Sprintf("unlock git vault: %v", err))
		}
		if err := v2.Batch(func() error {
			for name, value := range values {
				if err := v2.SetSecret(name, value, tagByName[name]); err != nil {
					return fmt.Errorf("set %s: %w", name, err)
				}
			}
			return nil
		}); err != nil {
			exitWithError(fmt.Sprintf("Migration failed: %v", err))
		}
		if err := gs.Sync(); err != nil {
			exitWithError(err.Error())
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

		_ = v2.Close()

		f.Success(fmt.Sprintf("Migrated %d secret(s) to git vault at %s", len(values), repoPath))
	},
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
