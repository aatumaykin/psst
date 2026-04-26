package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const gracefulShutdownDelay = 5 * time.Second

type ExecOptions struct {
	MaskOutput bool
}

type Runner struct{}

func New() *Runner {
	return &Runner{}
}

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

	expandedArgs := make([]string, len(args))
	for i, a := range args {
		expandedArgs[i] = ExpandEnvVars(a, secrets)
	}

	cmd := exec.CommandContext(ctx, command, expandedArgs...)
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

	waitErr := cmd.Wait()
	return exitCode(waitErr), waitErr
}

func streamWithMasking(src io.Reader, dst io.Writer, secrets []string) {
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
	var tail string

	for {
		n, readErr := src.Read(buf)
		data := tail + string(buf[:n])

		if len(data) == 0 {
			break
		}

		masked := MaskSecrets(data, secrets)

		if readErr != nil {
			_, _ = dst.Write([]byte(masked))
			break
		}

		if len(masked) > maxSecretLen {
			_, _ = dst.Write([]byte(masked[:len(masked)-maxSecretLen]))
			tail = masked[len(masked)-maxSecretLen:]
		} else {
			tail = masked
		}
	}
}

func buildEnv(secrets map[string][]byte) []string {
	env := os.Environ()
	for k, v := range secrets {
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

func filterEmpty(secrets map[string][]byte) []string {
	var result []string
	for _, v := range secrets {
		if len(v) > 0 {
			result = append(result, string(v))
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
