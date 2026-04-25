package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

const maxScanSize = 1024 * 1024

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
		<-sigCh
		cancel()
	}()
	defer signal.Stop(sigCh)

	env := buildEnv(secrets)

	expandedArgs := make([]string, len(args))
	for i, a := range args {
		expandedArgs[i] = ExpandEnvVars(a, secrets)
	}

	cmd := exec.CommandContext(ctx, command, expandedArgs...)
	cmd.Env = env

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

	reader := bufio.NewReaderSize(src, maxScanSize)
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			masked := MaskSecrets(line, secrets)
			_, _ = dst.Write([]byte(masked))
		}
		if readErr != nil {
			break
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
