# Versioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SemVer versioning to psst binary via goreleaser + ldflags, expose via `psst version` command, automate releases with GitHub Actions.

**Architecture:** Package `internal/version` holds build-time variables set via `-ldflags`. Cobra subcommand `psst version` renders them. goreleaser handles cross-platform builds on tag push.

**Tech Stack:** Go ldflags, spf13/cobra, goreleaser, GitHub Actions

---

### Task 1: Create version package

**Files:**
- Create: `internal/version/version.go`
- Create: `internal/version/version_test.go`

- [ ] **Step 1: Write the test for version package**

Create `internal/version/version_test.go`:

```go
package version

import (
	"runtime"
	"testing"
)

func TestStringDefaults(t *testing.T) {
	if Version != "dev" {
		t.Errorf("default Version = %q, want %q", Version, "dev")
	}
	if Commit != "none" {
		t.Errorf("default Commit = %q, want %q", Commit, "none")
	}
	if Date != "unknown" {
		t.Errorf("default Date = %q, want %q", Date, "unknown")
	}
}

func TestString(t *testing.T) {
	s := String()
	if s == "" {
		t.Fatal("String() returned empty string")
	}
	if !contains(s, "dev") {
		t.Errorf("String() should contain default version, got: %s", s)
	}
	if !contains(s, runtime.Version()) {
		t.Errorf("String() should contain Go version, got: %s", s)
	}
}

func TestJSON(t *testing.T) {
	info := JSON()
	if info.Version != Version {
		t.Errorf("JSON().Version = %q, want %q", info.Version, Version)
	}
	if info.Commit != Commit {
		t.Errorf("JSON().Commit = %q, want %q", info.Commit, Commit)
	}
	if info.Date != Date {
		t.Errorf("JSON().Date = %q, want %q", info.Date, Date)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("JSON().GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	if info.OSArch != runtime.GOOS+"/"+runtime.GOARCH {
		t.Errorf("JSON().OSArch = %q, want %q", info.OSArch, runtime.GOOS+"/"+runtime.GOARCH)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/version/ -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Write the version package implementation**

Create `internal/version/version.go`:

```go
package version

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go"`
	OSArch    string `json:"os_arch"`
}

func String() string {
	return fmt.Sprintf("psst %s\ncommit: %s\nbuilt:  %s\ngo:     %s\nos/arch: %s/%s",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func JSON() BuildInfo {
	return BuildInfo{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OSArch:    runtime.GOOS + "/" + runtime.GOARCH,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/version/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/version/version.go internal/version/version_test.go
git commit -m "feat: add internal/version package with ldflags support"
```

---

### Task 2: Add `psst version` command

**Files:**
- Create: `internal/cli/version.go`

- [ ] **Step 1: Write the version command**

Create `internal/cli/version.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show psst version",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		if f.IsJSON() {
			f.printVersionJSON()
			return
		}

		fmt.Fprint(cmd.OutOrStdout(), version.String()+"\n")
	},
}

func (f *Formatter) printVersionJSON() {
	info := version.JSON()
	f.printJSON(info)
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(versionCmd)
}
```

- [ ] **Step 2: Run tests to verify nothing is broken**

Run: `cd /root/projects/gitlab/tools/psst && go test ./... -v`
Expected: ALL PASS

- [ ] **Step 3: Build and test manually**

Run: `cd /root/projects/gitlab/tools/psst && go build -o psst ./cmd/psst/ && ./psst version`
Expected output:
```
psst dev
commit: none
built:  unknown
go:     go1.26.0
os/arch: linux/amd64
```

Run: `./psst version --json`
Expected: JSON output with version/commit/date/go/os_arch fields.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/version.go
git commit -m "feat: add psst version command"
```

---

### Task 3: Add integration test for version command

**Files:**
- Modify: `tests/integration_test.go`

- [ ] **Step 1: Add TestVersion to integration tests**

Append to `tests/integration_test.go`:

```go
func TestVersion(t *testing.T) {
	e := newTestEnv(t)
	stdout, _, code := e.run("version")
	if code != 0 {
		t.Fatalf("version failed: %s", stdout)
	}
	if !strings.Contains(stdout, "psst") {
		t.Fatalf("expected 'psst' in version output, got: %s", stdout)
	}
}

func TestVersionJSON(t *testing.T) {
	e := newTestEnv(t)
	stdout, _, code := e.run("version", "--json")
	if code != 0 {
		t.Fatalf("version --json failed: %s", stdout)
	}
	if !strings.Contains(stdout, `"version"`) {
		t.Fatalf("expected JSON with version field, got: %s", stdout)
	}
}
```

- [ ] **Step 2: Run integration tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./tests/ -v -run TestVersion`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration_test.go
git commit -m "test: add integration tests for version command"
```

---

### Task 4: Update Makefile with ldflags

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Update Makefile**

Replace the entire `Makefile` content:

```makefile
.PHONY: build test lint clean build-linux-amd64 build-linux-arm64 release snapshot

GOLANGCI_LINT_VERSION := v2.11.4
GOLANGCI_LINT := $(shell command -v golangci-lint 2> /dev/null)

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -s -w \
  -X github.com/aatumaykin/psst/internal/version.Version=$(VERSION) \
  -X github.com/aatumaykin/psst/internal/version.Commit=$(COMMIT) \
  -X github.com/aatumaykin/psst/internal/version.Date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o psst ./cmd/psst/

test:
	go test ./... -v

lint:
ifndef GOLANGCI_LINT
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)
endif
	golangci-lint run ./...

clean:
	rm -f psst

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o psst-linux-amd64 ./cmd/psst/

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o psst-linux-arm64 ./cmd/psst/

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean
```

- [ ] **Step 2: Build with ldflags and verify**

Run: `cd /root/projects/gitlab/tools/psst && make clean && make build && ./psst version`
Expected: version shows git tag or commit hash instead of "dev", real date instead of "unknown".

- [ ] **Step 3: Run full test suite**

Run: `cd /root/projects/gitlab/tools/psst && make test`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "feat: embed version via ldflags in Makefile build"
```

---

### Task 5: Add goreleaser config

**Files:**
- Create: `.goreleaser.yml`

- [ ] **Step 1: Create goreleaser config**

Create `.goreleaser.yml`:

```yaml
version: 2

builds:
  - main: ./cmd/psst
    ldflags:
      - -s -w -X github.com/aatumaykin/psst/internal/version.Version={{.Version}} -X github.com/aatumaykin/psst/internal/version.Commit={{.Commit}} -X github.com/aatumaykin/psst/internal/version.Date={{.Date}}
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64

archives:
  - format: tar.gz
    name_template: >-
      {{ .ProjectName }}_
      {{- .Version }}_
      {{- .Os }}_
      {{- .Arch }}
    format_overrides:
      - goos: windows
        format: zip

checksum:
  name_template: "checksums.txt"

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
      - "^chore:"

release:
  github:
    owner: aatumaykin
    name: psst
```

- [ ] **Step 2: Commit**

```bash
git add .goreleaser.yml
git commit -m "feat: add goreleaser config for cross-platform releases"
```

---

### Task 6: Add GitHub Actions release workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create release workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - uses: goreleaser/goreleaser-action@v6
        with:
          distribution: goreleaser
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat: add GitHub Actions release workflow"
```

---

### Task 7: Final verification

- [ ] **Step 1: Run lint**

Run: `cd /root/projects/gitlab/tools/psst && make lint`
Expected: no errors

- [ ] **Step 2: Run all tests**

Run: `cd /root/projects/gitlab/tools/psst && make test`
Expected: ALL PASS

- [ ] **Step 3: Build and verify version output**

Run: `cd /root/projects/gitlab/tools/psst && make clean && make build && ./psst version && ./psst version --json`
Expected: both human-readable and JSON output work correctly.
