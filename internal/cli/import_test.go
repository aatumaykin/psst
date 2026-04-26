package cli

import (
	"strings"
	"testing"
)

func TestParseEnvLine(t *testing.T) {
	tests := []struct {
		line      string
		wantName  string
		wantValue string
		wantOK    bool
	}{
		{"KEY=value", "KEY", "value", true},
		{"KEY=\"value\"", "KEY", "value", true},
		{"KEY='value'", "KEY", "value", true},
		{"KEY=\"\"", "KEY", "", true},
		{"KEY=''", "KEY", "", true},
		{"KEY=", "KEY", "", true},
		{"KEY=\"hello world\"", "KEY", "hello world", true},
		{"KEY='hello world'", "KEY", "hello world", true},
		{"KEY=\"value with \\\"quotes\\\"\"", "KEY", `value with "quotes"`, true},
		{"KEY=\"path\\\\to\\\\file\"", "KEY", `path\to\file`, true},
		{"KEY = value ", "KEY", "value", true},
		{"NOVALUE", "", "", false},
		{"KEY=mixed'quotes\"", "KEY", "mixed'quotes\"", true},
		{"KEY='unterminated", "KEY", "'unterminated", true},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, value, ok := parseEnvLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if value != tt.wantValue {
				t.Errorf("value = %q, want %q", value, tt.wantValue)
			}
		})
	}
}

func TestParseEnvFromReader(t *testing.T) {
	input := `# comment
KEY1=value1
KEY2="quoted value"
KEY3='single quoted'

KEY4=value4
`
	entries, err := parseEnvFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	if entries["KEY1"] != "value1" {
		t.Errorf("KEY1 = %q, want %q", entries["KEY1"], "value1")
	}
	if entries["KEY2"] != "quoted value" {
		t.Errorf("KEY2 = %q, want %q", entries["KEY2"], "quoted value")
	}
	if entries["KEY3"] != "single quoted" {
		t.Errorf("KEY3 = %q, want %q", entries["KEY3"], "single quoted")
	}
	if entries["KEY4"] != "value4" {
		t.Errorf("KEY4 = %q, want %q", entries["KEY4"], "value4")
	}
}
