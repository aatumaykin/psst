package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSplitLines(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"line1\nline2\nline3", []string{"line1", "line2", "line3"}},
		{"line1\r\nline2", []string{"line1", "line2"}},
		{"", nil},
		{"\n\n\n", nil},
		{"  spaced  \n  trim  ", []string{"spaced", "trim"}},
		{"single", []string{"single"}},
		{"a\n\nb", []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitLines(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("splitLines(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitLines(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsBinaryExtension(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"image.png", true},
		{"image.jpg", true},
		{"image.JPEG", true},
		{"archive.zip", true},
		{"archive.tar", true},
		{"archive.gz", true},
		{"binary.exe", true},
		{"binary.dll", true},
		{"lib.so", true},
		{"font.woff", true},
		{"font.woff2", true},
		{"font.ttf", true},
		{"video.mp4", true},
		{"audio.mp3", true},
		{"db.sqlite", true},
		{"data.db", true},
		{"main.go", false},
		{"config.yaml", false},
		{"README.md", false},
		{"script.sh", false},
		{"data.json", false},
		{"Makefile", false},
		{"Dockerfile", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isBinaryExtension(tt.path)
			if got != tt.want {
				t.Errorf("isBinaryExtension(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestScanFile_MatchesSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "code.txt")
	os.WriteFile(path, []byte("db_password=hunter2\nother=stuff\n"), 0644)

	secrets := map[string][]byte{
		"DB_PASS": []byte("hunter2"),
	}

	matches, warnings := scanFile(path, secrets)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].SecretName != "DB_PASS" {
		t.Errorf("secret name = %q, want %q", matches[0].SecretName, "DB_PASS")
	}
	if matches[0].Line != 1 {
		t.Errorf("line = %d, want 1", matches[0].Line)
	}
}

func TestScanFile_NoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.txt")
	os.WriteFile(path, []byte("nothing to see here\n"), 0644)

	secrets := map[string][]byte{
		"KEY": []byte("secretval"),
	}

	matches, _ := scanFile(path, secrets)
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}

func TestScanFile_SecretTooShort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.txt")
	os.WriteFile(path, []byte("key=abc\n"), 0644)

	secrets := map[string][]byte{
		"SHORT": []byte("abc"),
	}

	matches, _ := scanFile(path, secrets)
	if len(matches) != 0 {
		t.Fatalf("secrets < 4 bytes should not match, got %d", len(matches))
	}
}

func TestScanFile_BinaryExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.png")
	os.WriteFile(path, []byte("secret123"), 0644)

	secrets := map[string][]byte{
		"KEY": []byte("secret123"),
	}

	matches, warnings := scanFile(path, secrets)
	if len(matches) != 0 {
		t.Fatalf("binary extension should be skipped, got %d matches", len(matches))
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for binary ext, got %v", warnings)
	}
}

func TestScanFile_FileTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	bigData := make([]byte, 1024*1024+1)
	copy(bigData, []byte("secret123"))
	os.WriteFile(path, bigData, 0644)

	secrets := map[string][]byte{
		"KEY": []byte("secret123"),
	}

	matches, _ := scanFile(path, secrets)
	if len(matches) != 0 {
		t.Fatalf("files > 1MB should be skipped, got %d matches", len(matches))
	}
}

func TestScanFile_BOMPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.txt")
	bom := []byte{0xEF, 0xBB, 0xBF}
	data := make([]byte, 0, len(bom)+20)
	data = append(data, bom...)
	data = append(data, "token=mytoken123\n"...)
	os.WriteFile(path, data, 0644)

	secrets := map[string][]byte{
		"TOKEN": []byte("mytoken123"),
	}

	matches, _ := scanFile(path, secrets)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match in BOM file, got %d", len(matches))
	}
}

func TestScanFile_CRLF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crlf.txt")
	os.WriteFile(path, []byte("pass=mypass123\r\nother=stuff\r\n"), 0644)

	secrets := map[string][]byte{
		"PASS": []byte("mypass123"),
	}

	matches, _ := scanFile(path, secrets)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match in CRLF file, got %d", len(matches))
	}
}

func TestScanFile_NullByteStopsScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.txt")
	os.WriteFile(path, []byte("\x00binary_line\nkey=secret123\n"), 0644)

	secrets := map[string][]byte{
		"KEY": []byte("secret123"),
	}

	matches, _ := scanFile(path, secrets)
	if len(matches) != 0 {
		t.Fatalf("null byte line should stop scan, got %d matches", len(matches))
	}
}

func TestScanFile_NonexistentFile(t *testing.T) {
	secrets := map[string][]byte{
		"KEY": []byte("secret123"),
	}

	matches, warnings := scanFile("/nonexistent/path/file.txt", secrets)
	if len(matches) != 0 {
		t.Fatalf("expected no matches for missing file, got %d", len(matches))
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning for missing file")
	}
}

func TestScanFile_Directory(t *testing.T) {
	dir := t.TempDir()

	secrets := map[string][]byte{
		"KEY": []byte("secret123"),
	}

	matches, warnings := scanFile(dir, secrets)
	if len(matches) != 0 {
		t.Fatalf("expected no matches for directory, got %d", len(matches))
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for directory, got %v", warnings)
	}
}

func TestScanFile_MultipleMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.txt")
	os.WriteFile(path, []byte("a=hunter2\nb=hunter2\nc=safe\n"), 0644)

	secrets := map[string][]byte{
		"DB_PASS": []byte("hunter2"),
	}

	matches, _ := scanFile(path, secrets)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

func TestGetScanFiles_PathFlag(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "c.txt"), []byte("c"), 0644)

	files, err := getScanFiles(false, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d: %v", len(files), files)
	}
}

func TestGetScanFiles_NonexistentPath(t *testing.T) {
	files, err := getScanFiles(false, "/nonexistent/dir/that/does/not/exist")
	if err != nil {
		t.Fatalf("filepath.Walk does not error on nonexistent path: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected 0 files for nonexistent path, got %d", len(files))
	}
}

func TestGetScanFiles_GitNotAvailable(t *testing.T) {
	originalPath := os.Getenv("PATH")
	t.Cleanup(func() { t.Setenv("PATH", originalPath) })

	tmpDir := t.TempDir()
	t.Setenv("PATH", tmpDir)

	_, err := getScanFiles(false, "")
	if err == nil {
		t.Fatal("expected error when git not found")
	}
}
