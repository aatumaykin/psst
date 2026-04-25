package updater

import (
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
