# Versioning Design

## Goal

Add SemVer versioning to psst: embed version into binary, expose via `psst version` command, automate releases via goreleaser + GitHub Actions.

## Architecture

### 1. Version package — `internal/version/version.go`

Three `var` strings set via `-ldflags` at build time:

```go
var (
    Version = "dev"
    Commit  = "none"
    Date    = "unknown"
)
```

Defaults (`dev`, `none`, `unknown`) used for local `go build` without ldflags.

Function `String()` returns human-readable multi-line output. Function `JSON()` returns structured data for `--json` flag.

### 2. Version command — `internal/cli/version.go`

Cobra subcommand `psst version`.

Human-readable output:
```
psst v1.0.1
commit: 98c6cde
built:  2026-04-24T15:30:00Z
go:     go1.26.0
os/arch: linux/amd64
```

With `--json` flag:
```json
{"version":"v1.0.1","commit":"98c6cde","date":"2026-04-24T15:30:00Z","go":"go1.26.0","os_arch":"linux/amd64"}
```

### 3. goreleaser config — `.goreleaser.yml`

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

Produces 6 binaries: linux/darwin/windows x amd64/arm64.

### 4. GitHub Actions — `.github/workflows/release.yml`

Trigger: push tag `v*`.

Steps:
1. Checkout with `fetch-depth: 0` (goreleaser needs full history)
2. Setup Go 1.26
3. Run goreleaser with `GITHUB_TOKEN`

### 5. Makefile updates

- `build` target: add ldflags using `git describe --tags --always --dirty` for local dev
- New `release` target: `goreleaser release --clean`
- New `snapshot` target: `goreleaser release --snapshot --clean` (for testing without tag)

```makefile
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -s -w \
  -X github.com/aatumaykin/psst/internal/version.Version=$(VERSION) \
  -X github.com/aatumaykin/psst/internal/version.Commit=$(COMMIT) \
  -X github.com/aatumaykin/psst/internal/version.Date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o psst ./cmd/psst/

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean
```

## Files to create

| File                              | Action   |
| --------------------------------- | -------- |
| `internal/version/version.go`     | Create   |
| `internal/cli/version.go`         | Create   |
| `.goreleaser.yml`                 | Create   |
| `.github/workflows/release.yml`   | Create   |
| `Makefile`                        | Modify   |

## Release workflow

1. Merge PR to `main`
2. `git tag v1.1.0 && git push origin v1.1.0`
3. GitHub Actions triggers → goreleaser builds 6 binaries → creates GitHub Release with archives + checksums

## Constraints

- No new Go dependencies (goreleaser is a dev tool, not imported)
- Existing commands, tests, and architecture unchanged
- `psst version` respects existing `--json` and `--quiet` global flags
