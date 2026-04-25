package updater

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
