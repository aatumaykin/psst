package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

type VaultConfig struct {
	Storage string
	Remote  string
	PinSalt string
	HasPin  bool
	PinKDF  crypto.KDFParams
}

func configPath(envDir string) string {
	return filepath.Join(envDir, "config.yaml")
}

func LoadVaultConfig(envDir string) (*VaultConfig, error) {
	data, err := os.ReadFile(configPath(envDir))
	if err != nil {
		if os.IsNotExist(err) {
			return &VaultConfig{}, nil
		}
		return nil, fmt.Errorf("read vault config: %w", err)
	}
	cfg := &VaultConfig{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid vault config: line %d: not key: value", i+1)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "storage":
			cfg.Storage = value
		case "remote":
			cfg.Remote = value
		case "pin_salt":
			cfg.PinSalt = value
		case "pin_kdf_time":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid vault config: pin_kdf_time: %w", err)
			}
			cfg.PinKDF.Time = uint32(n)
		case "pin_kdf_memory":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid vault config: pin_kdf_memory: %w", err)
			}
			cfg.PinKDF.Memory = uint32(n)
		case "pin_kdf_threads":
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid vault config: pin_kdf_threads: %w", err)
			}
			cfg.PinKDF.Threads = uint8(n)
		}
	}
	cfg.HasPin = cfg.PinSalt != ""
	return cfg, nil
}

func SaveVaultConfig(envDir string, cfg VaultConfig) error {
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}
	var b strings.Builder
	if cfg.Storage != "" {
		b.WriteString("storage: " + cfg.Storage + "\n")
	}
	if cfg.Remote != "" {
		b.WriteString("remote: " + cfg.Remote + "\n")
	}
	if cfg.PinSalt != "" {
		b.WriteString("pin_salt: " + cfg.PinSalt + "\n")
		b.WriteString("pin_kdf_time: " + strconv.FormatUint(uint64(cfg.PinKDF.Time), 10) + "\n")
		b.WriteString("pin_kdf_memory: " + strconv.FormatUint(uint64(cfg.PinKDF.Memory), 10) + "\n")
		b.WriteString("pin_kdf_threads: " + strconv.FormatUint(uint64(cfg.PinKDF.Threads), 10) + "\n")
	}
	path := configPath(envDir)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write vault config: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod vault config: %w", err)
	}
	return nil
}

func ResolveStorage(flagVal string, envDir string) (string, error) {
	if flagVal != "" {
		if flagVal != "sqlite" && flagVal != "git" {
			return "", fmt.Errorf("invalid storage %q: must be sqlite or git", flagVal)
		}
		return flagVal, nil
	}
	cfg, err := LoadVaultConfig(envDir)
	if err != nil {
		return "", err
	}
	if cfg.Storage != "" {
		if cfg.Storage != "sqlite" && cfg.Storage != "git" {
			return "", fmt.Errorf("invalid storage %q in config: must be sqlite or git", cfg.Storage)
		}
		return cfg.Storage, nil
	}
	dbExists := statExists(vault.SQLitePath(envDir))
	repoExists := statExists(filepath.Join(envDir, "repo"))
	yamlExists := statExists(filepath.Join(envDir, "repo", "psst.yaml"))
	if dbExists && (repoExists || yamlExists) {
		return "", fmt.Errorf("conflicting storage markers in %s", envDir)
	}
	if yamlExists {
		return "git", nil
	}
	return "sqlite", nil
}

func statExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ValidateRemoteScheme(remote string, allowInsecure bool) error {
	if remote == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(remote, "ssh://"), strings.HasPrefix(remote, "https://"), strings.HasPrefix(remote, "git@"):
		return nil
	case strings.HasPrefix(remote, "http://"):
		if allowInsecure {
			return nil
		}
		return errors.New("http:// remote requires --allow-insecure-remote")
	case strings.HasPrefix(remote, "git://"):
		return errors.New("git:// remote is not allowed (plaintext transport)")
	}
	if statExists(remote) {
		return nil
	}
	return fmt.Errorf("unsupported remote %q: allowed are ssh://, https://, git@host:path, http:// (with --allow-insecure-remote) and existing filesystem paths", remote)
}

func OpenVaultStore(envDir, storage, remote string, allowInsecure bool) (store.SecretStore, *store.GitStore, error) {
	if storage == "git" {
		if err := ValidateRemoteScheme(remote, allowInsecure); err != nil {
			return nil, nil, err
		}
		cfg, err := LoadVaultConfig(envDir)
		if err != nil {
			return nil, nil, err
		}
		effRemote := remote
		if effRemote == "" {
			effRemote = cfg.Remote
		}
		loadPins := func() *store.Pin {
			cur, err := LoadVaultConfig(envDir)
			if err != nil || cur.PinSalt == "" {
				return nil
			}
			return &store.Pin{SaltB64: cur.PinSalt, Params: cur.PinKDF}
		}
		savePins := func(p store.Pin) error {
			cur, err := LoadVaultConfig(envDir)
			if err != nil {
				return err
			}
			cur.PinSalt = p.SaltB64
			cur.HasPin = p.SaltB64 != ""
			cur.PinKDF = p.Params
			return SaveVaultConfig(envDir, *cur)
		}
		gs, err := store.NewGitStore(filepath.Join(envDir, "repo"), store.GitOptions{
			Remote:              effRemote,
			AllowInsecureRemote: allowInsecure,
			LoadPins:            loadPins,
			SavePins:            savePins,
		})
		if err != nil {
			return nil, nil, err
		}
		return gs, gs, nil
	}
	s, err := store.NewSQLite(vault.SQLitePath(envDir))
	if err != nil {
		return nil, nil, err
	}
	return s, nil, nil
}
