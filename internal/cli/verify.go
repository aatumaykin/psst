package cli

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

const exitCodeError = 2

type verifyOpts struct {
	Expected string
	Hash     string
}

func runVerify(ctx context.Context, v vault.Interface, name string, opts verifyOpts) error {
	if err := requireValidName(name); err != nil {
		return err
	}

	if opts.Expected == "" && opts.Hash == "" {
		fmt.Fprintf(os.Stderr, "✗ Exactly one of --expected or --hash is required\n")
		return &exitError{code: exitCodeError}
	}
	if opts.Expected != "" && opts.Hash != "" {
		fmt.Fprintf(os.Stderr, "✗ Cannot use both --expected and --hash\n")
		return &exitError{code: exitCodeError}
	}

	sec, err := v.GetSecret(ctx, name)
	if err != nil {
		return &exitError{code: exitCodeError}
	}
	defer crypto.ZeroBytes(sec.Value)

	var match bool
	if opts.Hash != "" {
		expectedHash, decErr := hex.DecodeString(opts.Hash)
		if decErr != nil {
			return exitWithError(fmt.Sprintf("Invalid hash: %v", decErr))
		}
		computedHash := sha256.Sum256(sec.Value)
		match = subtle.ConstantTimeCompare(computedHash[:], expectedHash) == 1
	} else {
		expected := []byte(opts.Expected)
		match = subtle.ConstantTimeCompare(sec.Value, expected) == 1
	}

	if match {
		fmt.Fprintf(os.Stdout, "✓ %s matches\n", name)
		return nil
	}
	fmt.Fprintf(os.Stderr, "✗ %s does not match\n", name)
	return &exitError{code: 1}
}

var verifyCmd = &cobra.Command{
	Use:   "verify <name>",
	Short: "Verify a secret value without revealing it",
	Long: `Compare a secret against an expected value or SHA-256 hash without revealing the actual value.

Exit codes: 0 = match, 1 = no match, 2 = error`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		expected, _ := cmd.Flags().GetString("expected")
		hash, _ := cmd.Flags().GetString("hash")

		return withVault(cmd, func(v vault.Interface, _ *output.Formatter) error {
			return runVerify(cmd.Context(), v, name, verifyOpts{
				Expected: expected,
				Hash:     hash,
			})
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	verifyCmd.Flags().String("expected", "", "Expected plaintext value (visible in /proc/PID/cmdline)")
	verifyCmd.Flags().String("hash", "", "Expected SHA-256 hex digest")
	rootCmd.AddCommand(verifyCmd)
}
