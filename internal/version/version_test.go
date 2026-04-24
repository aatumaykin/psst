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
