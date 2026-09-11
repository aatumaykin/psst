package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/aatumaykin/psst/internal/crypto"
)

var (
	ErrSaltChanged  = errors.New("vault salt changed")
	ErrKDFWeakened  = errors.New("vault KDF parameters weakened or mixed")
	ValidTag        = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	ValidSecretName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

type VaultMeta struct {
	Version int
	KDFAlgo string
	Params  crypto.KDFParams
	SaltB64 string
	Cipher  string
}

type Pin struct {
	SaltB64 string
	Params  crypto.KDFParams
}

func NewVaultMeta(saltB64 string, params crypto.KDFParams) *VaultMeta {
	return &VaultMeta{Version: 1, KDFAlgo: "argon2id", Params: params, SaltB64: saltB64, Cipher: "aes-256-gcm"}
}

func ParseVaultMeta(data []byte) (*VaultMeta, error) {
	seen := make(map[string]string)
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("invalid vault metadata: line %d: not key: value", i+1)
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("invalid vault metadata: duplicate key %q", key)
		}
		seen[key] = value
	}

	m := &VaultMeta{}
	for _, key := range []string{"version", "kdf_algo", "kdf_time", "kdf_memory", "kdf_threads", "salt", "cipher"} {
		if _, ok := seen[key]; !ok {
			return nil, fmt.Errorf("invalid vault metadata: missing key %q", key)
		}
	}
	for key := range seen {
		switch key {
		case "version", "kdf_algo", "kdf_time", "kdf_memory", "kdf_threads", "salt", "cipher":
		default:
			return nil, fmt.Errorf("invalid vault metadata: unknown key %q", key)
		}
	}

	if seen["version"] != "1" {
		return nil, fmt.Errorf("invalid vault metadata: unsupported version %q", seen["version"])
	}
	m.Version = 1

	if seen["kdf_algo"] != "argon2id" {
		return nil, fmt.Errorf("invalid vault metadata: unsupported kdf_algo %q", seen["kdf_algo"])
	}
	m.KDFAlgo = seen["kdf_algo"]

	var err error
	if m.Params.Time, err = parseUintField(seen["kdf_time"], "kdf_time", 3); err != nil {
		return nil, err
	}
	if m.Params.Memory, err = parseUintField(seen["kdf_memory"], "kdf_memory", 65536); err != nil {
		return nil, err
	}
	threads, err := parseUintField(seen["kdf_threads"], "kdf_threads", 1)
	if err != nil {
		return nil, err
	}
	if threads > 255 {
		return nil, fmt.Errorf("invalid vault metadata: kdf_threads out of range")
	}
	m.Params.Threads = uint8(threads)

	salt, err := base64.StdEncoding.DecodeString(seen["salt"])
	if err != nil {
		return nil, fmt.Errorf("invalid vault metadata: salt is not valid base64: %w", err)
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("invalid vault metadata: salt too short: %d bytes", len(salt))
	}
	m.SaltB64 = seen["salt"]

	if seen["cipher"] != "aes-256-gcm" {
		return nil, fmt.Errorf("invalid vault metadata: unsupported cipher %q", seen["cipher"])
	}
	m.Cipher = seen["cipher"]

	return m, nil
}

func parseUintField(value, key string, min uint32) (uint32, error) {
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid vault metadata: %s is not a valid number: %w", key, err)
	}
	if n < uint64(min) {
		return 0, fmt.Errorf("invalid vault metadata: %s = %d is below minimum %d", key, n, min)
	}
	return uint32(n), nil
}

func (m *VaultMeta) Encode() []byte {
	return []byte("version: " + strconv.Itoa(m.Version) + "\n" +
		"kdf_algo: " + m.KDFAlgo + "\n" +
		"kdf_time: " + strconv.FormatUint(uint64(m.Params.Time), 10) + "\n" +
		"kdf_memory: " + strconv.FormatUint(uint64(m.Params.Memory), 10) + "\n" +
		"kdf_threads: " + strconv.FormatUint(uint64(m.Params.Threads), 10) + "\n" +
		"salt: " + m.SaltB64 + "\n" +
		"cipher: " + m.Cipher + "\n")
}

func CheckPinned(meta *VaultMeta, pin *Pin) error {
	if pin == nil {
		return nil
	}
	if meta.SaltB64 != pin.SaltB64 {
		return ErrSaltChanged
	}
	p, m := pin.Params, meta.Params
	if p == m {
		return nil
	}
	if m.Time >= p.Time && m.Memory >= p.Memory && m.Threads >= p.Threads {
		return nil
	}
	return ErrKDFWeakened
}

func (m *VaultMeta) AAD() []byte {
	return []byte("psst:v1:" + m.KDFAlgo + ":" + m.SaltB64)
}

func (m *VaultMeta) Fingerprint() string {
	return m.SaltB64 + "|" + strconv.FormatUint(uint64(m.Params.Time), 10) + "|" +
		strconv.FormatUint(uint64(m.Params.Memory), 10) + "|" +
		strconv.FormatUint(uint64(m.Params.Threads), 10)
}

func EncodeSecretFile(ciphertext, iv []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(append(append([]byte{}, iv...), ciphertext...)) + "\n")
}

func DecodeSecretFile(data []byte) (ciphertext, iv []byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(string(data), " \n"))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid secret file: %w", err)
	}
	if len(raw) < 12 {
		return nil, nil, fmt.Errorf("invalid secret file: IV shorter than 12 bytes")
	}
	return raw[12:], raw[:12], nil
}

func SecretPath(secretsRoot, name, tag string) (string, error) {
	if !ValidSecretName.MatchString(name) {
		return "", fmt.Errorf("invalid secret name %q", name)
	}
	if tag != "" && !ValidTag.MatchString(tag) {
		return "", fmt.Errorf("invalid tag %q", tag)
	}
	if tag == "" {
		return filepath.Join(secretsRoot, name+".enc"), nil
	}
	return filepath.Join(secretsRoot, tag, name+".enc"), nil
}
