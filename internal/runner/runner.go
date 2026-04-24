package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type ExecOptions struct {
	MaskOutput bool
}

type Runner struct{}

func New() *Runner {
	return &Runner{}
}

func (r *Runner) Exec(secrets map[string]string, command string, args []string, opts ExecOptions) (int, error) {
	env := buildEnv(secrets)

	expandedArgs := make([]string, len(args))
	for i, a := range args {
		expandedArgs[i] = ExpandEnvVars(a, secrets)
	}

	cmd := exec.Command(command, expandedArgs...)
	cmd.Env = env

	if opts.MaskOutput {
		return r.runWithMasking(cmd, secrets)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return exitCode(err), err
}

func (r *Runner) runWithMasking(cmd *exec.Cmd, secrets map[string]string) (int, error) {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 1, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 1, err
	}
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return 1, err
	}

	secretValues := filterEmpty(secrets)

	go streamWithMasking(stdoutPipe, os.Stdout, secretValues)
	go streamWithMasking(stderrPipe, os.Stderr, secretValues)

	err = cmd.Wait()
	return exitCode(err), err
}

func streamWithMasking(src io.Reader, dst io.Writer, secrets []string) {
	maxLen := 0
	for _, s := range secrets {
		if len(s) > maxLen {
			maxLen = len(s)
		}
	}

	overlap := 0
	buf := make([]byte, 4096)
	carry := make([]byte, 0, maxLen)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := append(carry, buf[:n]...)

			if overlap > 0 && len(chunk) > overlap {
				masked := MaskSecrets(string(chunk), secrets)
				safeEnd := len(chunk) - overlap
				if safeEnd > len(masked) {
					safeEnd = len(masked)
				}
				dst.Write([]byte(masked[:safeEnd]))
				carry = append(carry[:0], chunk[len(chunk)-overlap:]...)
			} else {
				masked := MaskSecrets(string(chunk), secrets)
				dst.Write([]byte(masked))
				carry = carry[:0]
			}
		}
		if err != nil {
			if len(carry) > 0 {
				masked := MaskSecrets(string(carry), secrets)
				dst.Write([]byte(masked))
			}
			return
		}
		if maxLen > 0 {
			overlap = maxLen - 1
		}
	}
}

func buildEnv(secrets map[string]string) []string {
	env := os.Environ()
	for k, v := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	var filtered []string
	for _, e := range env {
		if !strings.HasPrefix(e, "PSST_PASSWORD=") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func filterEmpty(secrets map[string]string) []string {
	var result []string
	for _, v := range secrets {
		if len(v) > 0 {
			result = append(result, v)
		}
	}
	return result
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}
