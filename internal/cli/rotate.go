package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

func readNewPassword(useStdin bool) (string, error) {
	if useStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password: %w", err)
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return "", errors.New("empty password on stdin")
		}
		return pw, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) { //nolint:gosec // fd fits int on supported platforms
		return "", errors.New("no terminal available: pass the new password via --stdin")
	}
	fmt.Fprint(os.Stderr, "New password: ")
	b1, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // fd fits int on supported platforms
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(os.Stderr, "Confirm: ")
	b2, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // fd fits int on supported platforms
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(b1) != string(b2) {
		return "", errors.New("passwords do not match")
	}
	if len(b1) == 0 {
		return "", errors.New("empty password")
	}
	return string(b1), nil
}

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate vault key: new salt, all secrets re-encrypted in one commit",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		f := getFormatter(cfg.JSON, cfg.Quiet)
		ctx := cmd.Context()
		useStdin, _ := cmd.Flags().GetBool("stdin")
		useKDF, _ := cmd.Flags().GetBool("kdf")

		envDir, err := vault.FindVaultDir(cfg.Global, cfg.Env)
		if err != nil {
			return exitWithError(err.Error())
		}
		storage, err := ResolveStorage(cfg.Storage, envDir)
		if err != nil {
			return exitWithError(err.Error())
		}
		if storage != storageGit {
			return exitWithError("psst rotate requires git storage; run 'psst migrate storage --to git'")
		}
		if !statExists(filepath.Join(envDir, "repo", ".git")) {
			printNoVault(cfg.JSON, cfg.Quiet)
			return &exitError{code: ExitNoVault}
		}
		s, gs, err := OpenVaultStore(envDir, storageGit, "", false)
		if err != nil {
			return exitWithError(fmt.Sprintf("open vault: %v", err))
		}
		if err = s.InitSchema(); err != nil {
			return exitWithError(err.Error())
		}
		enc := crypto.NewAESGCM()
		v := vault.New(enc, keyring.NewPasswordProvider(enc, true), s)
		if err = v.Unlock(ctx); err != nil {
			printAuthFailed(cfg.JSON, cfg.Quiet)
			return &exitError{code: ExitAuthFailed}
		}
		defer v.Close()

		metas, err := v.ListSecrets(ctx)
		if err != nil {
			return exitWithError(err.Error())
		}
		if err = v.VerifyAllDecryptable(ctx); err != nil {
			return exitWithError("rotate aborted: " + err.Error())
		}
		newPassword, err := readNewPassword(useStdin)
		if err != nil {
			return exitWithError(err.Error())
		}
		var target *crypto.KDFParams
		if useKDF {
			defaults := crypto.DefaultKDFParams()
			target = &defaults
		}
		n, err := v.Rotate(ctx, newPassword, target)
		if err != nil {
			return exitWithError(err.Error() +
				"; working tree may be dirty; run 'psst sync --discard-local' to reset to the remote (pre-rotation) state")
		}
		repinErr := repinVault(ctx, envDir, gs)
		msg := fmt.Sprintf("Rotated: %d secrets re-encrypted", n)
		if repinErr != nil {
			f.Warning("Re-pin failed: " + repinErr.Error() + "; run 'psst sync --accept-rotation'")
			msg += "; re-pin failed — run 'psst sync --accept-rotation'"
		} else {
			msg += ", new salt pinned"
		}
		if len(metas) == 0 {
			msg += " (password not verified: vault is empty)"
		}
		f.Success(msg)
		return nil
	},
}

func repinVault(ctx context.Context, envDir string, gs *store.GitStore) error {
	saltB64, err := gs.GetMeta(ctx, "kdf_salt")
	if err != nil {
		return err
	}
	cfg, err := LoadVaultConfig(envDir)
	if err != nil {
		return err
	}
	cfg.PinSalt = saltB64
	tv, _ := gs.GetMeta(ctx, "kdf_time")
	mv, _ := gs.GetMeta(ctx, "kdf_memory")
	th, _ := gs.GetMeta(ctx, "kdf_threads")
	cfg.PinKDF.Time = uint32(atoiDefault(tv))   //nolint:gosec // value fits: mirrors validated psst.yaml pins
	cfg.PinKDF.Memory = uint32(atoiDefault(mv)) //nolint:gosec // value fits: mirrors validated psst.yaml pins
	cfg.PinKDF.Threads = uint8(atoiDefault(th)) //nolint:gosec // value fits: mirrors validated psst.yaml pins
	return SaveVaultConfig(envDir, *cfg)
}

func atoiDefault(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rotateCmd.Flags().Bool("stdin", false, "Read the new password from stdin (one line)")
	rotateCmd.Flags().Bool("kdf", false, "Strengthen KDF parameters to defaults in the same commit")
	rootCmd.AddCommand(rotateCmd)
}
