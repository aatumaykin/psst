package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/server"
	"github.com/aatumaykin/psst/internal/vault"
)

var errNoVault = errors.New("no vault found")

const (
	defaultListen     = "127.0.0.1:7788"
	minServeTimeout   = time.Minute
	sessionTTL        = 24 * time.Hour
	tokenSize         = 32
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 5 * time.Second
)

func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

func resolveServeToken(flagVal string) (string, bool, error) {
	if flagVal != "" {
		return flagVal, false, nil
	}
	if env := os.Getenv("PSST_SERVE_TOKEN"); env != "" {
		return env, false, nil
	}
	b := make([]byte, tokenSize)
	if _, err := rand.Read(b); err != nil {
		return "", false, fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), true, nil
}

func serveStorageGate(envDir, storageFlag string) error {
	storage, err := ResolveStorage(storageFlag, envDir)
	if err != nil {
		return err
	}
	repoExists := statExists(filepath.Join(envDir, "repo", ".git")) ||
		statExists(filepath.Join(envDir, "repo", "psst.yaml"))
	if storage == storageGit {
		if !repoExists {
			return errNoVault
		}
		return nil
	}
	dbExists := statExists(vault.SQLitePath(envDir))
	if dbExists || repoExists {
		return errors.New("psst serve requires git storage; run 'psst migrate storage --to git'")
	}
	return errNoVault
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the web UI server (git storage only)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		listen, _ := cmd.Flags().GetString("listen")
		tokenFlag, _ := cmd.Flags().GetString("token")
		timeoutStr, _ := cmd.Flags().GetString("timeout")
		if listen == "" {
			listen = defaultListen
		}
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return exitWithError(fmt.Sprintf("invalid --timeout: %v", err))
		}
		if timeout < minServeTimeout {
			return exitWithError("--timeout must be at least 1m")
		}
		envDir, err := vault.FindVaultDir(cfg.Global, cfg.Env)
		if err != nil {
			return exitWithError(err.Error())
		}
		if err = serveStorageGate(envDir, cfg.Storage); err != nil {
			if errors.Is(err, errNoVault) {
				printNoVault(cfg.JSON, cfg.Quiet)
				return &exitError{code: ExitNoVault}
			}
			return exitWithError(err.Error())
		}
		s, gs, err := OpenVaultStore(envDir, storageGit, "", false)
		if err != nil {
			return exitWithError(fmt.Sprintf("open vault: %v", err))
		}
		if err = s.InitSchema(); err != nil {
			return exitWithError(fmt.Sprintf("init vault: %v", err))
		}
		host, port, err := net.SplitHostPort(listen)
		if err != nil {
			return exitWithError(fmt.Sprintf("invalid --listen %q: %v", listen, err))
		}
		if !isLoopbackHost(host) {
			fmt.Fprintln(os.Stderr, "warning: listening on a non-loopback interface; "+
				"expose only via SSH tunnel (ssh -L 7788:127.0.0.1:7788)")
		}
		token, generated, err := resolveServeToken(tokenFlag)
		if err != nil {
			return exitWithError(err.Error())
		}
		digest := sha256.Sum256([]byte(token))
		srv := server.New(server.Config{
			Store: gs, Enc: crypto.NewAESGCM(),
			Host: host, Port: port,
			TokenDigest:   digest,
			UnlockTimeout: timeout,
			SessionTTL:    sessionTTL,
		})
		httpSrv := &http.Server{
			Addr:              listen,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					srv.Sweep()
				}
			}
		}()
		errCh := make(chan error, 1)
		go func() { errCh <- httpSrv.ListenAndServe() }()
		fmt.Fprintf(os.Stdout, "psst server:  http://%s\n", listen)
		if generated {
			fmt.Fprintf(os.Stdout, "auth token:   %s   (shown once)\n", token)
		}
		select {
		case srvErr := <-errCh:
			if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
				return exitWithError(fmt.Sprintf("serve: %v", srvErr))
			}
		case <-ctx.Done():
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		srv.Close()
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	serveCmd.Flags().String("listen", defaultListen, "Listen address")
	serveCmd.Flags().String("token", "", "Auth token (reads PSST_SERVE_TOKEN env; generated when empty)")
	serveCmd.Flags().String("timeout", "30m", "Unlock inactivity timeout (minimum 1m)")
	rootCmd.AddCommand(serveCmd)
}
