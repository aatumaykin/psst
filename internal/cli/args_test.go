package cli

import "testing"

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
