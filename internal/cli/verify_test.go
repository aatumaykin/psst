package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestVerifyExpected_Match(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"API_KEY": []byte("secret123"),
		},
	}

	err := runVerify(context.Background(), v, "API_KEY", verifyOpts{Expected: "secret123"})
	if err != nil {
		t.Fatalf("expected match, got error: %v", err)
	}
}

func TestVerifyExpected_NoMatch(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"API_KEY": []byte("secret123"),
		},
	}

	err := runVerify(context.Background(), v, "API_KEY", verifyOpts{Expected: "wrong"})
	if err == nil {
		t.Fatal("expected no-match error")
	}

	var exitErr *exitError
	if !isExitError(err, &exitErr) {
		t.Fatalf("expected exitError, got %T: %v", err, err)
	}
	if exitErr.code != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.code)
	}
}

func TestVerifyHash_Match(t *testing.T) {
	secret := []byte("secret123")
	hash := sha256.Sum256(secret)
	hashHex := fmt.Sprintf("%x", hash[:])

	v := &mockVault{
		secrets: map[string][]byte{
			"API_KEY": secret,
		},
	}

	err := runVerify(context.Background(), v, "API_KEY", verifyOpts{Hash: hashHex})
	if err != nil {
		t.Fatalf("expected match, got error: %v", err)
	}
}

func TestVerifyHash_NoMatch(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"API_KEY": []byte("secret123"),
		},
	}

	err := runVerify(context.Background(), v, "API_KEY", verifyOpts{Hash: "0000000000000000"})
	if err == nil {
		t.Fatal("expected no-match error")
	}

	var exitErr *exitError
	if !isExitError(err, &exitErr) {
		t.Fatalf("expected exitError, got %T: %v", err, err)
	}
	if exitErr.code != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.code)
	}
}

func TestVerify_SecretNotFound(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{},
	}

	err := runVerify(context.Background(), v, "MISSING", verifyOpts{Expected: "val"})
	if err == nil {
		t.Fatal("expected error for missing secret")
	}

	var exitErr *exitError
	if !isExitError(err, &exitErr) {
		t.Fatalf("expected exitError, got %T: %v", err, err)
	}
	if exitErr.code != 2 {
		t.Fatalf("exit code = %d, want 2", exitErr.code)
	}
}

func TestVerify_NoFlags(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"KEY": []byte("val"),
		},
	}

	err := runVerify(context.Background(), v, "KEY", verifyOpts{})
	if err == nil {
		t.Fatal("expected error when no flags provided")
	}

	var exitErr *exitError
	if !isExitError(err, &exitErr) {
		t.Fatalf("expected exitError, got %T: %v", err, err)
	}
	if exitErr.code != 2 {
		t.Fatalf("exit code = %d, want 2", exitErr.code)
	}
}

func TestVerify_BothFlags(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"KEY": []byte("val"),
		},
	}

	err := runVerify(context.Background(), v, "KEY", verifyOpts{Expected: "val", Hash: "abc"})
	if err == nil {
		t.Fatal("expected error when both flags provided")
	}

	var exitErr *exitError
	if !isExitError(err, &exitErr) {
		t.Fatalf("expected exitError, got %T: %v", err, err)
	}
	if exitErr.code != 2 {
		t.Fatalf("exit code = %d, want 2", exitErr.code)
	}
}

func TestVerify_InvalidName(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{},
	}

	err := runVerify(context.Background(), v, "bad-name", verifyOpts{Expected: "val"})
	if err == nil {
		t.Fatal("expected error for invalid name")
	}
}
