package updater

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

func TestCompareVersionsSemverPrerelease(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-rc", -1},
		{"1.0.0-rc", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-rc", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0-rc", "1.0.0-beta", 1},
		{"1.0.0-dev", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-alpha", 0},
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

func TestParseChecksums(t *testing.T) {
	data := `abc123  psst_1.2.3_linux_amd64.tar.gz
def456  psst_1.2.3_linux_arm64.tar.gz
789abc  checksums.txt
`
	got := parseChecksums([]byte(data))
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
	got := parseChecksums([]byte(""))
	if len(got) != 0 {
		t.Errorf("len(checksums) = %d, want 0", len(got))
	}
}

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

	data, readErr := os.ReadFile(oldPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "new" {
		t.Errorf("old binary content = %q, want %q", string(data), "new")
	}

	if _, statErr := os.Stat(newPath); !os.IsNotExist(statErr) {
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
	if writeErr := tw.WriteHeader(hdr); writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, writeContentErr := tw.Write(content); writeContentErr != nil {
		t.Fatal(writeContentErr)
	}

	tw.Close()
	gw.Close()
	f.Close()

	return archivePath
}
