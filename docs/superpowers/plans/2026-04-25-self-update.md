# Self-Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `psst update check` and `psst update` commands to check for new versions and perform in-place binary self-update from GitHub Releases.

**Architecture:** New leaf package `internal/updater` with no dependencies beyond stdlib and `internal/version`. CLI wiring in `internal/cli/update.go`. Uses GitHub Releases API for version discovery, SHA256 checksums from goreleaser for verification, atomic rename for binary replacement.

**Tech Stack:** Go stdlib (`net/http`, `archive/tar`, `compress/gzip`, `crypto/sha256`, `os`, `runtime`), Cobra CLI

---

## File Structure

| File | Responsibility |
|------|---------------|
| `internal/updater/updater.go` | Types, semver comparison, update orchestration |
| `internal/updater/github.go` | GitHub Releases API client |
| `internal/updater/verify.go` | SHA256 checksum parsing and verification |
| `internal/updater/install.go` | Download, extract, atomic binary replacement |
| `internal/updater/updater_test.go` | All unit tests |
| `internal/cli/update.go` | Cobra command registration |

---

### Task 1: Semver comparison and types

**Files:**
- Create: `internal/updater/updater.go`
- Test: `internal/updater/updater_test.go`

- [ ] **Step 1: Write failing tests for semver comparison and types**

Create `internal/updater/updater_test.go`:

```go
package updater

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.0", "1.3.0", -1},
		{"1.10.0", "1.9.0", 1},
		{"0.1.0", "1.0.0", -1},
		{"1.0.0", "0.1.0", 1},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCompareVersionsWithVPrefix(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.0.0", "v1.0.0", 0},
		{"v1.0.0", "v1.0.1", -1},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0", "v1.0.1", -1},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCompareVersionsWithPrerelease(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0-beta", 1},
		{"1.0.0-beta", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0-beta", "1.0.0-beta", 0},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCompareVersionsInvalid(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"dev", "1.0.0", -1},
		{"1.0.0", "dev", 1},
		{"dev", "dev", 0},
		{"", "", 0},
		{"1.0.0", "", 1},
		{"", "1.0.0", -1},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestBuildAssetName(t *testing.T) {
	tests := []struct {
		version, goos, goarch string
		want                  string
	}{
		{"v1.2.3", "linux", "amd64", "psst_1.2.3_linux_amd64.tar.gz"},
		{"v1.2.3", "linux", "arm64", "psst_1.2.3_linux_arm64.tar.gz"},
		{"v1.2.3", "darwin", "amd64", "psst_1.2.3_darwin_amd64.tar.gz"},
		{"v1.2.3", "darwin", "arm64", "psst_1.2.3_darwin_arm64.tar.gz"},
		{"v1.2.3", "windows", "amd64", "psst_1.2.3_windows_amd64.zip"},
		{"v1.2.3", "windows", "arm64", "psst_1.2.3_windows_arm64.zip"},
	}
	for _, tt := range tests {
		got := buildAssetName(tt.version, tt.goos, tt.goarch)
		if got != tt.want {
			t.Errorf("buildAssetName(%q, %q, %q) = %q, want %q", tt.version, tt.goos, tt.goarch, got, tt.want)
		}
	}
}

func TestUpdateInfoIsNewer(t *testing.T) {
	info := &UpdateInfo{LatestVersion: "2.0.0", CurrentVersion: "1.0.0"}
	if !info.IsNewer() {
		t.Error("expected IsNewer() = true when latest > current")
	}

	info2 := &UpdateInfo{LatestVersion: "1.0.0", CurrentVersion: "1.0.0"}
	if info2.IsNewer() {
		t.Error("expected IsNewer() = false when versions match")
	}

	info3 := &UpdateInfo{LatestVersion: "0.9.0", CurrentVersion: "1.0.0"}
	if info3.IsNewer() {
		t.Error("expected IsNewer() = false when latest < current")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/updater/ -v -run "TestCompareVersions|TestBuildAssetName|TestUpdateInfo"`
Expected: FAIL (package does not exist)

- [ ] **Step 3: Write implementation**

Create `internal/updater/updater.go`:

```go
package updater

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/aatumaykin/psst/internal/version"
)

type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
	DownloadURL    string
	ChecksumURL    string
	AssetName      string
}

type ReleaseInfo struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func CheckForUpdate() (*UpdateInfo, error) {
	release, err := fetchLatestRelease()
	if err != nil {
		return nil, fmt.Errorf("check for update: %w", err)
	}

	currentVer := strings.TrimPrefix(version.Version, "v")
	latestVer := strings.TrimPrefix(release.TagName, "v")

	assetName := buildAssetName(release.TagName, runtime.GOOS, runtime.GOARCH)

	var downloadURL, checksumURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.URL
		}
		if asset.Name == "checksums.txt" {
			checksumURL = asset.URL
		}
	}

	if downloadURL == "" {
		return nil, fmt.Errorf("no binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	return &UpdateInfo{
		CurrentVersion: currentVer,
		LatestVersion:  latestVer,
		DownloadURL:    downloadURL,
		ChecksumURL:    checksumURL,
		AssetName:      assetName,
	}, nil
}

func (u *UpdateInfo) IsNewer() bool {
	return compareVersions(u.LatestVersion, u.CurrentVersion) > 0
}

func buildAssetName(tag, goos, goarch string) string {
	ver := strings.TrimPrefix(tag, "v")
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("psst_%s_%s_%s%s", ver, goos, goarch, ext)
}

func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aParts := strings.SplitN(a, "-", 2)
	bParts := strings.SplitN(b, "-", 2)

	cmp := compareVersionParts(aParts[0], bParts[0])
	if cmp != 0 {
		return cmp
	}

	aPre := ""
	bPre := ""
	if len(aParts) > 1 {
		aPre = aParts[1]
	}
	if len(bParts) > 1 {
		bPre = bParts[1]
	}

	if aPre == "" && bPre == "" {
		return 0
	}
	if aPre == "" {
		return 1
	}
	if bPre == "" {
		return -1
	}
	if aPre < bPre {
		return -1
	}
	if aPre > bPre {
		return 1
	}
	return 0
}

func compareVersionParts(a, b string) int {
	aNums := strings.Split(a, ".")
	bNums := strings.Split(b, ".")

	maxLen := len(aNums)
	if len(bNums) > maxLen {
		maxLen = len(bNums)
	}

	for i := range maxLen {
		aVal := 0
		bVal := 0
		if i < len(aNums) {
			aVal, _ = strconv.Atoi(aNums[i])
		}
		if i < len(bNums) {
			bVal, _ = strconv.Atoi(bNums[i])
		}
		if aVal != bVal {
			if aVal < bVal {
				return -1
			}
			return 1
		}
	}
	return 0
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/updater/ -v -run "TestCompareVersions|TestBuildAssetName|TestUpdateInfo"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/updater/updater.go internal/updater/updater_test.go
git commit -m "feat(update): add semver comparison and update types"
```

---

### Task 2: GitHub Releases API client

**Files:**
- Create: `internal/updater/github.go`
- Test: `internal/updater/updater_test.go` (append tests)

- [ ] **Step 1: Write failing tests for GitHub API client**

Append to `internal/updater/updater_test.go`:

```go
func TestFetchLatestRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/aatumaykin/psst/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
			"tag_name": "v1.2.3",
			"assets": [
				{"name": "psst_1.2.3_linux_amd64.tar.gz", "browser_download_url": "https://example.com/psst_1.2.3_linux_amd64.tar.gz"},
				{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums.txt"}
			]
		}`)
	}))
	defer server.Close()

	release, err := fetchLatestReleaseWithURL(server.URL + "/repos/aatumaykin/psst/releases/latest")
	if err != nil {
		t.Fatalf("fetchLatestReleaseWithURL() error: %v", err)
	}
	if release.TagName != "v1.2.3" {
		t.Errorf("TagName = %q, want %q", release.TagName, "v1.2.3")
	}
	if len(release.Assets) != 2 {
		t.Fatalf("len(Assets) = %d, want 2", len(release.Assets))
	}
	if release.Assets[0].Name != "psst_1.2.3_linux_amd64.tar.gz" {
		t.Errorf("Asset[0].Name = %q, want %q", release.Assets[0].Name, "psst_1.2.3_linux_amd64.tar.gz")
	}
}

func TestFetchLatestReleaseRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `{"message": "API rate limit exceeded"}`)
	}))
	defer server.Close()

	_, err := fetchLatestReleaseWithURL(server.URL + "/repos/aatumaykin/psst/releases/latest")
	if err == nil {
		t.Fatal("expected error for rate limit")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("error = %q, want rate limit message", err.Error())
	}
}

func TestFetchLatestReleaseNetworkError(t *testing.T) {
	_, err := fetchLatestReleaseWithURL("http://127.0.0.1:1/bad")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/updater/ -v -run "TestFetchLatestRelease"`
Expected: FAIL (function does not exist)

- [ ] **Step 3: Write implementation**

Create `internal/updater/github.go`:

```go
package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultGitHubAPIURL = "https://api.github.com/repos/aatumaykin/psst/releases/latest"

var httpClient = &http.Client{Timeout: 15 * time.Second}

func fetchLatestRelease() (*ReleaseInfo, error) {
	return fetchLatestReleaseWithURL(defaultGitHubAPIURL)
}

func fetchLatestReleaseWithURL(apiURL string) (*ReleaseInfo, error) {
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("GitHub API rate limit exceeded. Try again later")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}

	if release.TagName == "" {
		return nil, fmt.Errorf("release has no tag name")
	}

	return &release, nil
}

func downloadFile(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}

	var buf strings.Builder
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("download %s: read body: %w", url, err)
	}

	return []byte(buf.String()), nil
}
```

- [ ] **Step 4: Add required imports to test file**

Ensure `internal/updater/updater_test.go` imports include:

```go
import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/updater/ -v -run "TestFetchLatestRelease"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/updater/github.go internal/updater/updater_test.go
git commit -m "feat(update): add GitHub Releases API client"
```

---

### Task 3: SHA256 checksum verification

**Files:**
- Create: `internal/updater/verify.go`
- Test: `internal/updater/updater_test.go` (append tests)

- [ ] **Step 1: Write failing tests for checksum verification**

Append to `internal/updater/updater_test.go`:

```go
func TestParseChecksums(t *testing.T) {
	data := `abc123  psst_1.2.3_linux_amd64.tar.gz
def456  psst_1.2.3_linux_arm64.tar.gz
789abc  checksums.txt
`
	got, err := parseChecksums([]byte(data))
	if err != nil {
		t.Fatalf("parseChecksums() error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(checksums) = %d, want 3", len(got))
	}
	if got["psst_1.2.3_linux_amd64.tar.gz"] != "abc123" {
		t.Errorf("checksum for linux_amd64 = %q, want %q", got["psst_1.2.3_linux_amd64.tar.gz"], "abc123")
	}
	if got["psst_1.2.3_linux_arm64.tar.gz"] != "def456" {
		t.Errorf("checksum for linux_arm64 = %q, want %q", got["psst_1.2.3_linux_arm64.tar.gz"], "def456")
	}
}

func TestVerifyChecksum(t *testing.T) {
	content := []byte("hello world")
	h := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(h[:])

	checksums := map[string]string{"test.txt": expectedHash}

	if err := verifyChecksum(checksums, "test.txt", content); err != nil {
		t.Errorf("verifyChecksum() error: %v", err)
	}

	if err := verifyChecksum(checksums, "test.txt", []byte("wrong")); err == nil {
		t.Error("expected error for mismatched checksum")
	}

	if err := verifyChecksum(checksums, "missing.txt", content); err == nil {
		t.Error("expected error for missing filename")
	}
}

func TestParseChecksumsEmpty(t *testing.T) {
	got, err := parseChecksums([]byte(""))
	if err != nil {
		t.Fatalf("parseChecksums() error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len(checksums) = %d, want 0", len(got))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/updater/ -v -run "TestParseChecksums|TestVerifyChecksum"`
Expected: FAIL (functions do not exist)

- [ ] **Step 3: Write implementation**

Create `internal/updater/verify.go`:

```go
package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func parseChecksums(data []byte) (map[string]string, error) {
	checksums := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			continue
		}
		checksums[parts[1]] = parts[0]
	}
	return checksums, nil
}

func verifyChecksum(checksums map[string]string, filename string, data []byte) error {
	expected, ok := checksums[filename]
	if !ok {
		return fmt.Errorf("no checksum found for %s", filename)
	}

	h := sha256.Sum256(data)
	actual := hex.EncodeToString(h[:])

	if actual != expected {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", filename, expected, actual)
	}

	return nil
}
```

- [ ] **Step 4: Add required imports to test file**

Ensure test file imports include:

```go
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/updater/ -v -run "TestParseChecksums|TestVerifyChecksum"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/updater/verify.go internal/updater/updater_test.go
git commit -m "feat(update): add SHA256 checksum parsing and verification"
```

---

### Task 4: Download, extract, and atomic binary replacement

**Files:**
- Create: `internal/updater/install.go`
- Test: `internal/updater/updater_test.go` (append tests)

- [ ] **Step 1: Write failing tests for install logic**

Append to `internal/updater/updater_test.go`:

```go
func TestExtractBinaryFromTarGz(t *testing.T) {
	dir := t.TempDir()

	binaryContent := []byte("#!/bin/bash\necho psst")
	archivePath := createTestTarGz(t, dir, "psst", binaryContent)

	got, err := extractBinaryFromTarGz(archivePath)
	if err != nil {
		t.Fatalf("extractBinaryFromTarGz() error: %v", err)
	}
	if string(got) != string(binaryContent) {
		t.Errorf("extracted content = %q, want %q", string(got), string(binaryContent))
	}
}

func TestExtractBinaryFromTarGzNotFound(t *testing.T) {
	dir := t.TempDir()
	archivePath := createTestTarGz(t, dir, "other-binary", []byte("data"))

	_, err := extractBinaryFromTarGz(archivePath)
	if err == nil {
		t.Fatal("expected error when binary not found in archive")
	}
}

func TestReplaceBinary(t *testing.T) {
	dir := t.TempDir()

	oldPath := filepath.Join(dir, "psst-old")
	newPath := filepath.Join(dir, "psst-new")

	if err := os.WriteFile(oldPath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceBinary(oldPath, newPath); err != nil {
		t.Fatalf("replaceBinary() error: %v", err)
	}

	data, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Errorf("old binary content = %q, want %q", string(data), "new")
	}

	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Error("new binary should be removed after replacement")
	}
}

func createTestTarGz(t *testing.T, dir, name string, content []byte) string {
	t.Helper()

	archivePath := filepath.Join(dir, "archive.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()
	f.Close()

	return archivePath
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/updater/ -v -run "TestExtractBinary|TestReplaceBinary"`
Expected: FAIL (functions do not exist)

- [ ] **Step 3: Write implementation**

Create `internal/updater/install.go`:

```go
package updater

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func PerformUpdate(info *UpdateInfo, force bool) error {
	if !force && !info.IsNewer() {
		return fmt.Errorf("already up to date (v%s)", info.CurrentVersion)
	}

	checksumData, err := downloadFile(info.ChecksumURL)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}

	archiveData, err := downloadFile(info.DownloadURL)
	if err != nil {
		return fmt.Errorf("download archive: %w", err)
	}

	checksums, err := parseChecksums(checksumData)
	if err != nil {
		return fmt.Errorf("parse checksums: %w", err)
	}

	if err := verifyChecksum(checksums, info.AssetName, archiveData); err != nil {
		return fmt.Errorf("verify checksum: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "psst-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, info.AssetName)
	if err := os.WriteFile(archivePath, archiveData, 0o644); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}

	binaryData, err := extractBinaryFromTarGz(archivePath)
	if err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	if runtime.GOOS == "windows" {
		return fmt.Errorf("windows update not yet supported via tar.gz extraction")
	}

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find current binary: %w", err)
	}

	newBinaryPath := filepath.Join(tmpDir, "psst-new")
	if err := os.WriteFile(newBinaryPath, binaryData, 0o755); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}

	if err := replaceBinary(currentExe, newBinaryPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	return nil
}

func extractBinaryFromTarGz(archivePath string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}

		if hdr.Name == "psst" || filepath.Base(hdr.Name) == "psst" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read binary from tar: %w", err)
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("binary 'psst' not found in archive")
}

func replaceBinary(currentPath, newPath string) error {
	if err := os.Chmod(newPath, 0o755); err != nil {
		return fmt.Errorf("chmod new binary: %w", err)
	}

	backupPath := currentPath + ".bak"
	if err := os.Rename(currentPath, backupPath); err != nil {
		if err := copyFile(newPath, currentPath); err != nil {
			return fmt.Errorf("copy over current binary: %w", err)
		}
		return os.Remove(newPath)
	}

	if err := os.Rename(newPath, currentPath); err != nil {
		_ = os.Rename(backupPath, currentPath)
		return fmt.Errorf("rename new binary: %w", err)
	}

	_ = os.Remove(backupPath)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}
```

- [ ] **Step 4: Add required imports to test file**

Ensure test file imports include:

```go
import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/updater/ -v -run "TestExtractBinary|TestReplaceBinary"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/updater/install.go internal/updater/updater_test.go
git commit -m "feat(update): add download, extract and atomic binary replacement"
```

---

### Task 5: CLI command wiring

**Files:**
- Create: `internal/cli/update.go`

- [ ] **Step 1: Write the CLI command**

Create `internal/cli/update.go`:

```go
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/updater"
	"github.com/aatumaykin/psst/internal/version"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update psst to the latest version",
}

var updateCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if a newer version is available",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		info, err := updater.CheckForUpdate()
		if err != nil {
			exitWithError(fmt.Sprintf("Update check failed: %v", err))
		}

		if jsonOut {
			f.PrintJSON(map[string]string{
				"current": version.Version,
				"latest":  info.LatestVersion,
				"update":  fmt.Sprintf("%v", info.IsNewer()),
			})
			return
		}

		if quiet {
			if info.IsNewer() {
				fmt.Fprintln(os.Stdout, info.LatestVersion)
			}
			return
		}

		fmt.Fprintf(os.Stdout, "Current: v%s\n", info.CurrentVersion)
		fmt.Fprintf(os.Stdout, "Latest:  v%s\n", info.LatestVersion)

		if info.IsNewer() {
			fmt.Fprintf(os.Stdout, "\nUpdate available! Run: psst update\n")
		} else {
			fmt.Fprintf(os.Stdout, "\nAlready up to date.\n")
		}
	},
}

var updateInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Download and install the latest version",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		_ = getFormatter(jsonOut, quiet)
		force, _ := cmd.Flags().GetBool("force")

		info, err := updater.CheckForUpdate()
		if err != nil {
			exitWithError(fmt.Sprintf("Update check failed: %v", err))
		}

		if !force && !info.IsNewer() {
			if !quiet {
				fmt.Fprintf(os.Stdout, "Already up to date (v%s). Use --force to reinstall.\n", info.CurrentVersion)
			}
			return
		}

		if !quiet {
			fmt.Fprintf(os.Stdout, "Updating from v%s to v%s...\n", info.CurrentVersion, info.LatestVersion)
		}

		if err := updater.PerformUpdate(info, force); err != nil {
			exitWithError(fmt.Sprintf("Update failed: %v", err))
		}

		if !quiet {
			fmt.Fprintf(os.Stdout, "Successfully updated to v%s!\n", info.LatestVersion)
		}
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	updateInstallCmd.Flags().Bool("force", false, "Reinstall even if already up to date")
	updateCmd.AddCommand(updateCheckCmd)
	updateCmd.AddCommand(updateInstallCmd)
	rootCmd.AddCommand(updateCmd)
}
```

- [ ] **Step 2: Verify build succeeds**

Run: `make build`
Expected: Build succeeds with no errors

- [ ] **Step 3: Verify command is registered**

Run: `./psst update --help`
Expected: Shows `check` and `install` subcommands

Run: `./psst update check --help`
Expected: Shows check help text

- [ ] **Step 4: Commit**

```bash
git add internal/cli/update.go
git commit -m "feat(update): add psst update check and psst update install CLI commands"
```

---

### Task 6: Run all tests and lint

**Files:** No new files

- [ ] **Step 1: Run full test suite**

Run: `make test`
Expected: All tests pass

- [ ] **Step 2: Run linter**

Run: `make lint`
Expected: No errors

- [ ] **Step 3: Run build**

Run: `make build`
Expected: Binary built successfully
