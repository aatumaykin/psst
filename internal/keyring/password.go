package keyring

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

type PasswordProvider struct {
	deriver     KeyDeriver
	allowPrompt bool
	once        sync.Once
	password    string
	promptErr   error
}

func NewPasswordProvider(deriver KeyDeriver, allowPrompt bool) *PasswordProvider {
	return &PasswordProvider{deriver: deriver, allowPrompt: allowPrompt}
}

func (p *PasswordProvider) resolve() (string, error) {
	if pw := os.Getenv("PSST_PASSWORD"); pw != "" {
		return pw, nil
	}
	if p.allowPrompt && term.IsTerminal(int(os.Stdin.Fd())) { //nolint:gosec // fd fits int on supported platforms
		p.once.Do(func() {
			fmt.Fprint(os.Stderr, "Enter vault password: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // fd fits int on supported platforms
			fmt.Fprintln(os.Stderr)
			if err != nil {
				p.promptErr = fmt.Errorf("read password: %w", err)
				return
			}
			if len(b) == 0 {
				p.promptErr = errors.New("empty password")
				return
			}
			p.password = string(b)
		})
		return p.password, p.promptErr
	}
	return "", errors.New("PSST_PASSWORD not set and no terminal available")
}

func (p *PasswordProvider) GetRawKey(_, _ string) ([]byte, error) {
	pw, err := p.resolve()
	if err != nil {
		return nil, err
	}
	return []byte(pw), nil
}

func (p *PasswordProvider) SetKey(_, _ string, _ []byte) error {
	return errors.New("password provider is read-only")
}

func (p *PasswordProvider) IsAvailable() bool {
	_, err := p.resolve()
	return err == nil
}

func (p *PasswordProvider) GenerateKey() ([]byte, error) {
	if p.deriver != nil {
		return p.deriver.GenerateKey()
	}
	return nil, errors.New("no key deriver available")
}

type fixedProvider struct {
	password string
}

func NewFixedProvider(password string) KeyProvider {
	return &fixedProvider{password: password}
}

func (p *fixedProvider) GetRawKey(_, _ string) ([]byte, error) {
	return []byte(p.password), nil
}

func (p *fixedProvider) SetKey(_, _ string, _ []byte) error {
	return errors.New("fixed provider is read-only")
}

func (p *fixedProvider) IsAvailable() bool {
	return true
}

func (p *fixedProvider) GenerateKey() ([]byte, error) {
	return nil, errors.New("fixed provider cannot generate keys")
}
