package version

import (
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
