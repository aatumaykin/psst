package cli

import (
	"os"
	"testing"
)

func TestFilterSubcommandNames(t *testing.T) {
	tests := []struct {
		input []string
		want  []string
	}{
		{[]string{"run"}, nil},
		{[]string{"list"}, nil},
		{[]string{"get"}, nil},
		{[]string{"set"}, nil},
		{[]string{"rm"}, nil},
		{[]string{"MY_SECRET"}, []string{"MY_SECRET"}},
		{[]string{"MY_SECRET", "run"}, []string{"MY_SECRET"}},
		{[]string{"run", "API_KEY"}, []string{"API_KEY"}},
		{[]string{}, nil},
	}
	for _, tt := range tests {
		got := filterSubcommandNames(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("filterSubcommandNames(%v) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("filterSubcommandNames(%v) = %v, want %v", tt.input, got, tt.want)
			}
		}
	}
}

func TestParseGlobalFlagsFromArgs_EqualsSyntax(t *testing.T) {
	os.Unsetenv("PSST_GLOBAL")
	os.Unsetenv("PSST_ENV")

	tests := []struct {
		name       string
		args       []string
		wantEnv    string
		wantTags   []string
		wantJSON   bool
		wantQuiet  bool
		wantGlobal bool
	}{
		{
			name:     "--env=equals",
			args:     []string{"--env=prod", "API_KEY", "--", "echo"},
			wantEnv:  "prod",
			wantTags: nil,
		},
		{
			name:     "--tag=equals",
			args:     []string{"--tag=aws", "API_KEY", "--", "echo"},
			wantTags: []string{"aws"},
		},
		{
			name:    "--env space",
			args:    []string{"--env", "staging", "KEY", "--", "echo"},
			wantEnv: "staging",
		},
		{
			name:     "--tag space",
			args:     []string{"--tag", "gcp", "KEY", "--", "echo"},
			wantTags: []string{"gcp"},
		},
		{
			name:     "mixed equals and space",
			args:     []string{"--env=prod", "--tag", "aws", "--json", "KEY", "--", "echo"},
			wantEnv:  "prod",
			wantTags: []string{"aws"},
			wantJSON: true,
		},
		{
			name:     "multiple tags with equals",
			args:     []string{"--tag=aws", "--tag=gcp", "KEY", "--", "echo"},
			wantTags: []string{"aws", "gcp"},
		},
		{
			name:      "--quiet short",
			args:      []string{"-q", "KEY", "--", "echo"},
			wantQuiet: true,
		},
		{
			name:       "--global short",
			args:       []string{"-g", "KEY", "--", "echo"},
			wantGlobal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseGlobalFlagsFromArgs(tt.args)
			if cfg.Env != tt.wantEnv {
				t.Errorf("env = %q, want %q", cfg.Env, tt.wantEnv)
			}
			if cfg.JSON != tt.wantJSON {
				t.Errorf("jsonOut = %v, want %v", cfg.JSON, tt.wantJSON)
			}
			if cfg.Quiet != tt.wantQuiet {
				t.Errorf("quiet = %v, want %v", cfg.Quiet, tt.wantQuiet)
			}
			if cfg.Global != tt.wantGlobal {
				t.Errorf("global = %v, want %v", cfg.Global, tt.wantGlobal)
			}
			if len(cfg.Tags) != len(tt.wantTags) {
				t.Fatalf("tags = %v, want %v", cfg.Tags, tt.wantTags)
			}
			for i := range cfg.Tags {
				if cfg.Tags[i] != tt.wantTags[i] {
					t.Errorf("tags[%d] = %q, want %q", i, cfg.Tags[i], tt.wantTags[i])
				}
			}
		})
	}
}

func TestFilterSecretNames_EqualsSyntax(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "--env=prod filtered",
			args: []string{"--env=prod", "API_KEY", "--", "echo"},
			want: []string{"API_KEY", "echo"},
		},
		{
			name: "--tag=aws filtered",
			args: []string{"--tag=aws", "API_KEY", "--", "echo"},
			want: []string{"API_KEY", "echo"},
		},
		{
			name: "space --env filtered",
			args: []string{"--env", "prod", "API_KEY", "--", "echo"},
			want: []string{"API_KEY", "echo"},
		},
		{
			name: "space --tag filtered",
			args: []string{"--tag", "aws", "API_KEY", "--", "echo"},
			want: []string{"API_KEY", "echo"},
		},
		{
			name: "mixed flags",
			args: []string{"--env=prod", "--tag=aws", "--json", "KEY1", "KEY2"},
			want: []string{"KEY1", "KEY2"},
		},
		{
			name: "no flags",
			args: []string{"KEY1", "KEY2"},
			want: []string{"KEY1", "KEY2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterSecretNames(tt.args)
			if len(got) != len(tt.want) {
				t.Fatalf("filterSecretNames(%v) = %v, want %v", tt.args, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("filterSecretNames(%v)[%d] = %q, want %q", tt.args, i, got[i], tt.want[i])
				}
			}
		})
	}
}
