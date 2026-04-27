package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
)

const gracefulShutdownDelay = 5 * time.Second

var validEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ExecOptions controls subprocess execution behavior.
type ExecOptions struct {
	MaskOutput bool
	ExpandArgs bool
}

// Runner executes commands with secrets injected into the environment.
type Runner struct{}

// New creates a new Runner.
func New() *Runner {
	return &Runner{}
}

// Exec runs a command with secrets injected as environment variables.
func (r *Runner) Exec(secrets map[string][]byte, command string, args []string, opts ExecOptions) (int, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer signal.Stop(sigCh)

	env := buildEnv(secrets)

	command = ExpandEnvVars(command, secrets)

	if opts.ExpandArgs {
		expandedArgs := make([]string, len(args))
		for i, a := range args {
			expandedArgs[i] = ExpandEnvVars(a, secrets)
		}
		args = expandedArgs
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = env
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = gracefulShutdownDelay

	if opts.MaskOutput {
		return r.runWithMasking(cmd, secrets)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()
	return exitCode(runErr), runErr
}

func (r *Runner) runWithMasking(cmd *exec.Cmd, secrets map[string][]byte) (int, error) {
	stdoutPipe, pipeErr := cmd.StdoutPipe()
	if pipeErr != nil {
		return 1, pipeErr
	}
	stderrPipe, pipeErr := cmd.StderrPipe()
	if pipeErr != nil {
		return 1, pipeErr
	}
	cmd.Stdin = os.Stdin

	if startErr := cmd.Start(); startErr != nil {
		return 1, startErr
	}

	secretValues := filterEmpty(secrets)

	doneStdout := make(chan struct{})
	doneStderr := make(chan struct{})

	go func() {
		streamWithMasking(stdoutPipe, os.Stdout, secretValues)
		close(doneStdout)
	}()
	go func() {
		streamWithMasking(stderrPipe, os.Stderr, secretValues)
		close(doneStderr)
	}()

	<-doneStdout
	<-doneStderr

	for i := range secretValues {
		crypto.ZeroBytes(secretValues[i])
	}

	waitErr := cmd.Wait()
	return exitCode(waitErr), waitErr
}

func streamWithMasking(src io.Reader, dst io.Writer, secrets [][]byte) {
	if len(secrets) == 0 {
		_, _ = io.Copy(dst, src)
		return
	}

	maxSecretLen := 0
	for _, s := range secrets {
		if len(s) > maxSecretLen {
			maxSecretLen = len(s)
		}
	}

	const chunkSize = 32 * 1024
	buf := make([]byte, chunkSize)
	var tail []byte

	for {
		n, readErr := src.Read(buf)
		data := make([]byte, 0, len(tail)+n)
		data = append(data, tail...)
		data = append(data, buf[:n]...)
		crypto.ZeroBytes(tail)

		if len(data) == 0 {
			break
		}

		masked := MaskSecretsBytes(data, secrets)
		crypto.ZeroBytes(data)

		if readErr != nil {
			_, _ = dst.Write(masked)
			crypto.ZeroBytes(masked)
			break
		}

		if len(masked) > maxSecretLen {
			writeEnd := len(masked) - maxSecretLen
			_, _ = dst.Write(masked[:writeEnd])
			tail = make([]byte, maxSecretLen)
			copy(tail, masked[writeEnd:])
			crypto.ZeroBytes(masked)
		} else {
			tail = masked
		}
	}
}

func buildEnv(secrets map[string][]byte) []string {
	env := os.Environ()
	for k, v := range secrets {
		if !validEnvName.MatchString(k) {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", k, string(v)))
	}
	var filtered []string
	for _, e := range env {
		if !strings.HasPrefix(e, "PSST_PASSWORD=") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func filterEmpty(secrets map[string][]byte) [][]byte {
	var result [][]byte
	for _, v := range secrets {
		if len(v) > 0 {
			cp := make([]byte, len(v))
			copy(cp, v)
			result = append(result, cp)
		}
	}
	return result
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}
