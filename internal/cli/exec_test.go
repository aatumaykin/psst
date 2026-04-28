package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/aatumaykin/psst/internal/vault"
)

type mockVault struct {
	secrets         map[string][]byte
	secretsByTag    map[string][]byte
	getSecretErr    error
	getAllSecretsFn func(ctx context.Context) (map[string][]byte, error)
}

func (m *mockVault) GetSecret(_ context.Context, name string) (*vault.Secret, error) {
	if m.getSecretErr != nil {
		return nil, m.getSecretErr
	}
	val, ok := m.secrets[name]
	if !ok {
		return nil, vault.ErrSecretNotFound
	}
	return &vault.Secret{Name: name, Value: val}, nil
}

func (m *mockVault) GetAllSecrets(_ context.Context) (map[string][]byte, error) {
	if m.getAllSecretsFn != nil {
		return m.getAllSecretsFn(context.Background())
	}
	return m.secrets, nil
}

func (m *mockVault) GetSecretsByTagValues(_ context.Context, _ []string) (map[string][]byte, error) {
	return m.secretsByTag, nil
}

func (m *mockVault) ListSecrets(_ context.Context) ([]vault.SecretMeta, error) {
	var result []vault.SecretMeta
	for name := range m.secrets {
		result = append(result, vault.SecretMeta{Name: name})
	}
	return result, nil
}

func (m *mockVault) SetSecret(_ context.Context, _ string, _ []byte, _ []string) error {
	return nil
}

func (m *mockVault) DeleteSecret(_ context.Context, _ string) error {
	return nil
}

func (m *mockVault) GetHistory(_ context.Context, _ string) ([]vault.SecretHistoryEntry, error) {
	return nil, nil
}

func (m *mockVault) Rollback(_ context.Context, _ string, _ int) error {
	return nil
}

func (m *mockVault) AddTag(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockVault) RemoveTag(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockVault) GetSecretsByTags(_ context.Context, _ []string) ([]vault.SecretMeta, error) {
	return nil, nil
}

func (m *mockVault) GetSecretNamesByTags(_ context.Context, _ []string) ([]string, error) {
	return nil, nil
}

func (m *mockVault) Unlock(_ context.Context) error {
	return nil
}

func (m *mockVault) MigrateKDF(_ context.Context) error {
	return nil
}

func (m *mockVault) Close() error {
	return nil
}

func TestExecWithSecrets_AllSecrets(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"MY_VAR": []byte("hello"),
		},
	}

	err := execWithSecrets(context.Background(), v, nil, []string{"printenv", "MY_VAR"}, execConfig{
		NoMask: true,
	})
	if err != nil {
		t.Fatalf("execWithSecrets: %v", err)
	}
}

func TestExecWithSecrets_SpecificNames(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"KEY_A": []byte("val_a"),
			"KEY_B": []byte("val_b"),
		},
	}

	err := execWithSecrets(context.Background(), v, []string{"KEY_A"}, []string{"printenv", "KEY_A"}, execConfig{
		NoMask: true,
	})
	if err != nil {
		t.Fatalf("execWithSecrets: %v", err)
	}
}

func TestExecWithSecrets_ByTag(t *testing.T) {
	v := &mockVault{
		secretsByTag: map[string][]byte{
			"AWS_KEY": []byte("awssecret"),
		},
	}

	err := execWithSecrets(context.Background(), v, nil, []string{"printenv", "AWS_KEY"}, execConfig{
		Tags:   []string{"aws"},
		NoMask: true,
	})
	if err != nil {
		t.Fatalf("execWithSecrets with tags: %v", err)
	}
}

func TestExecWithSecrets_NoSecrets(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{},
	}

	err := execWithSecrets(context.Background(), v, nil, []string{"echo", "hello"}, execConfig{})
	if err == nil {
		t.Fatal("expected error for empty vault")
	}
}

func TestExecWithSecrets_SecretNotFound(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{},
	}

	err := execWithSecrets(context.Background(), v, []string{"MISSING"}, []string{"echo", "hello"}, execConfig{})
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestExecWithSecrets_InvalidName(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{},
	}

	err := execWithSecrets(context.Background(), v, []string{"bad-name"}, []string{"echo", "hello"}, execConfig{})
	if err == nil {
		t.Fatal("expected error for invalid secret name")
	}
}

func TestExecWithSecrets_ExitCodePropagation(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"KEY": []byte("val"),
		},
	}

	err := execWithSecrets(context.Background(), v, nil, []string{"false"}, execConfig{})
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}

	var exitErr *exitError
	if !isExitError(err, &exitErr) {
		t.Fatalf("expected exitError, got %T: %v", err, err)
	}
	if exitErr.code != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.code)
	}
}

func TestExecWithSecrets_NonexistentCommand(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"KEY": []byte("val"),
		},
	}

	err := execWithSecrets(context.Background(), v, nil, []string{"nonexistent_cmd_xyz_123"}, execConfig{})
	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}
}

func TestExecWithSecrets_GetAllSecretsError(t *testing.T) {
	v := &mockVault{
		getAllSecretsFn: func(_ context.Context) (map[string][]byte, error) {
			return nil, context.DeadlineExceeded
		},
	}

	err := execWithSecrets(context.Background(), v, nil, []string{"echo", "hello"}, execConfig{})
	if err == nil {
		t.Fatal("expected error when GetAllSecrets fails")
	}
}

func TestExecWithSecrets_Masking(t *testing.T) {
	v := &mockVault{
		secrets: map[string][]byte{
			"MY_SECRET": []byte("secret123"),
		},
	}

	err := execWithSecrets(context.Background(), v, nil, []string{"echo", "secret123"}, execConfig{})
	if err != nil {
		t.Fatalf("execWithSecrets with masking: %v", err)
	}
}

func isExitError(err error, target **exitError) bool {
	var ee *exitError
	if errors.As(err, &ee) {
		*target = ee
		return true
	}
	return false
}
