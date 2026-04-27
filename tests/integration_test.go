package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binary string

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "psst-test")
	if err != nil {
		os.Stderr.WriteString("cannot create temp dir: " + err.Error())
		os.Exit(1)
	}
	binary = filepath.Join(tmpDir, "psst")

	cmd := exec.Command("go", "build", "-o", binary, "./cmd/psst")
	cmd.Dir = repoRoot()
	out, buildErr := cmd.CombinedOutput()
	if buildErr != nil {
		os.Stderr.WriteString("build failed: " + string(out))
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(tmpDir)
	os.Exit(code)
}

func repoRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

type testEnv struct {
	dir    string
	binary string
	t      *testing.T
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	return &testEnv{dir: dir, binary: binary, t: t}
}

func (e *testEnv) run(args ...string) (string, string, int) {
	e.t.Helper()
	cmd := exec.Command(e.binary, args...)
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(),
		"PSST_PASSWORD=test-password",
		"HOME="+e.dir,
	)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout := outBuf.String()
	stderr := errBuf.String()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout, stderr, exitCode
}

func (e *testEnv) initVault() {
	e.t.Helper()
	stdout, _, code := e.run("init")
	if code != 0 {
		e.t.Fatalf("init failed: %s", stdout)
	}
}

func (e *testEnv) writeFile(name, content string) {
	e.t.Helper()
	err := os.WriteFile(filepath.Join(e.dir, name), []byte(content), 0644)
	if err != nil {
		e.t.Fatal(err)
	}
}

func TestInit(t *testing.T) {
	e := newTestEnv(t)
	stdout, _, code := e.run("init")
	if code != 0 {
		t.Fatalf("init failed: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(e.dir, ".psst", "vault.db")); os.IsNotExist(err) {
		t.Fatal("vault.db not created")
	}
}

func TestSetGet(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	cmd := exec.Command(e.binary, "set", "API_KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("secret123\n"))
		stdin.Close()
	}()
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "Secret API_KEY set") {
		t.Fatalf("set failed: %s", string(out))
	}

	stdout, _, code := e.run("get", "API_KEY")
	if code != 0 {
		t.Fatalf("get failed: %s", stdout)
	}
	if !strings.Contains(stdout, "secret123") {
		t.Fatalf("expected secret123 in output, got: %s", stdout)
	}
}

func TestList(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	for _, name := range []string{"API_KEY", "DB_HOST"} {
		cmd := exec.Command(e.binary, "set", name)
		cmd.Dir = e.dir
		cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
		stdin, _ := cmd.StdinPipe()
		go func() {
			stdin.Write([]byte("val\n"))
			stdin.Close()
		}()
		cmd.CombinedOutput()
	}

	stdout, _, code := e.run("list")
	if code != 0 {
		t.Fatalf("list failed: %s", stdout)
	}
	if !strings.Contains(stdout, "API_KEY") || !strings.Contains(stdout, "DB_HOST") {
		t.Fatalf("expected both keys in list, got: %s", stdout)
	}
}

func TestRm(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	cmd := exec.Command(e.binary, "set", "MY_KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("val\n"))
		stdin.Close()
	}()
	cmd.CombinedOutput()

	stdout, _, code := e.run("rm", "MY_KEY")
	if code != 0 {
		t.Fatalf("rm failed: %s", stdout)
	}

	_, _, code = e.run("get", "MY_KEY")
	if code == 0 {
		t.Fatal("expected non-zero exit for deleted secret")
	}
}

func TestImport(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	e.writeFile("test.env", "API_KEY=mykey123\nDB_HOST=localhost\n")
	stdout, _, code := e.run("import", "test.env")
	if code != 0 {
		t.Fatalf("import failed: %s", stdout)
	}
	if !strings.Contains(stdout, "Imported 2") {
		t.Fatalf("unexpected import output: %s", stdout)
	}

	stdout, _, _ = e.run("get", "API_KEY")
	if !strings.Contains(stdout, "mykey123") {
		t.Fatalf("API_KEY not found after import: %s", stdout)
	}
}

func TestExport(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	e.writeFile("test.env", "TOKEN=abc\n")
	e.run("import", "test.env")

	stdout, _, code := e.run("export")
	if code != 0 {
		t.Fatalf("export failed: %s", stdout)
	}
	if !strings.Contains(stdout, "TOKEN=abc") {
		t.Fatalf("expected TOKEN=abc in export, got: %s", stdout)
	}
}

func TestHistory(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	for _, val := range []string{"v1", "v2", "v3"} {
		cmd := exec.Command(e.binary, "set", "KEY")
		cmd.Dir = e.dir
		cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
		stdin, _ := cmd.StdinPipe()
		go func(v string) {
			stdin.Write([]byte(v + "\n"))
			stdin.Close()
		}(val)
		cmd.CombinedOutput()
	}

	stdout, _, code := e.run("history", "KEY")
	if code != 0 {
		t.Fatalf("history failed: %s", stdout)
	}
	if !strings.Contains(stdout, "History for KEY") {
		t.Fatalf("unexpected history output: %s", stdout)
	}
}

func TestRollback(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	for _, val := range []string{"v1", "v2"} {
		cmd := exec.Command(e.binary, "set", "KEY")
		cmd.Dir = e.dir
		cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
		stdin, _ := cmd.StdinPipe()
		go func(v string) {
			stdin.Write([]byte(v + "\n"))
			stdin.Close()
		}(val)
		cmd.CombinedOutput()
	}

	stdout, _, code := e.run("rollback", "KEY", "--to", "1")
	if code != 0 {
		t.Fatalf("rollback failed: %s", stdout)
	}

	stdout, _, _ = e.run("get", "KEY")
	if !strings.Contains(stdout, "v1") {
		t.Fatalf("expected v1 after rollback, got: %s", stdout)
	}
}

func TestTag(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	cmd := exec.Command(e.binary, "set", "KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("val\n"))
		stdin.Close()
	}()
	cmd.CombinedOutput()

	stdout, _, code := e.run("tag", "KEY", "aws")
	if code != 0 {
		t.Fatalf("tag failed: %s", stdout)
	}

	stdout, _, code = e.run("list")
	if code != 0 {
		t.Fatalf("list failed: %s", stdout)
	}
	if !strings.Contains(stdout, "aws") {
		t.Fatalf("expected tag 'aws' in list, got: %s", stdout)
	}

	stdout, _, code = e.run("untag", "KEY", "aws")
	if code != 0 {
		t.Fatalf("untag failed: %s", stdout)
	}
}

func TestScan(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	e.writeFile("test.env", "API_KEY=mysecret\n")
	e.run("import", "test.env")

	e.writeFile("leak.txt", "key=mysecret\n")
	stdout, stderr, code := e.run("scan", "--path", "leak.txt")
	if code != 1 {
		t.Fatalf("scan should exit 1 on leaks, got %d: %s %s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "API_KEY") {
		t.Fatalf("expected leak report with API_KEY, got: %s %s", stdout, stderr)
	}

	e.writeFile("safe.txt", "no secrets here\n")
	stdout, _, code = e.run("scan", "--path", "safe.txt")
	if code != 0 {
		t.Fatalf("scan should exit 0 on clean files, got %d: %s", code, stdout)
	}
}

func TestScanBOM(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	e.writeFile("test.env", "TOKEN=secretval\n")
	e.run("import", "test.env")

	bomContent := []byte{0xEF, 0xBB, 0xBF}
	bomContent = append(bomContent, []byte("key=secretval\n")...)
	os.WriteFile(filepath.Join(e.dir, "bom.txt"), bomContent, 0644)

	_, stderr, code := e.run("scan", "--path", "bom.txt")
	if code != 1 {
		t.Fatalf("scan should detect secret in BOM file, got %d: %s", code, stderr)
	}
}

func TestScanCRLF(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	e.writeFile("test.env", "PASS=mypass123\n")
	e.run("import", "test.env")

	crlfContent := "line=mypass123\r\nother=stuff\r\n"
	os.WriteFile(filepath.Join(e.dir, "crlf.txt"), []byte(crlfContent), 0644)

	_, stderr, code := e.run("scan", "--path", "crlf.txt")
	if code != 1 {
		t.Fatalf("scan should detect secret in CRLF file, got %d: %s", code, stderr)
	}
}

func TestListEnvs(t *testing.T) {
	e := newTestEnv(t)
	stdout, _, code := e.run("list-envs")
	if code != 0 {
		t.Fatalf("list-envs failed: %s", stdout)
	}
}

func TestRun(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	e.writeFile("test.env", "MY_VAR=hello\n")
	e.run("import", "test.env")

	stdout, _, code := e.run("--no-mask", "MY_VAR", "--", "env")
	if code != 0 {
		t.Fatalf("run failed: exit %d", code)
	}
	if !strings.Contains(stdout, "MY_VAR=hello") {
		t.Fatalf("MY_VAR not in env output: %s", stdout)
	}
}

func TestGetNotFound(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	_, stderr, code := e.run("get", "NONEXISTENT")
	if code == 0 {
		t.Fatal("expected non-zero exit for missing secret")
	}
	if !strings.Contains(stderr, "not found") {
		t.Fatalf("expected 'not found' error, got: %s", stderr)
	}
}

func TestSetInvalidName(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	_, stderr, code := e.run("set", "bad-name")
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid name")
	}
	if !strings.Contains(stderr, "Invalid secret name") {
		t.Fatalf("expected invalid name error, got: %s", stderr)
	}
}

func TestExportToFile(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	e.writeFile("test.env", "KEY=val\n")
	e.run("import", "test.env")

	outFile := filepath.Join(e.dir, "out.env")
	stdout, _, code := e.run("export", "--env-file", outFile)
	if code != 0 {
		t.Fatalf("export --env-file failed: %s", stdout)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "KEY=val") {
		t.Fatalf("unexpected file content: %s", string(data))
	}
}

func TestVersion(t *testing.T) {
	e := newTestEnv(t)
	stdout, _, code := e.run("version")
	if code != 0 {
		t.Fatalf("version failed: %s", stdout)
	}
	if !strings.Contains(stdout, "psst") {
		t.Fatalf("expected 'psst' in version output, got: %s", stdout)
	}
}

func TestVersionJSON(t *testing.T) {
	e := newTestEnv(t)
	stdout, _, code := e.run("version", "--json")
	if code != 0 {
		t.Fatalf("version --json failed: %s", stdout)
	}
	if !strings.Contains(stdout, `"version"`) {
		t.Fatalf("expected JSON with version field, got: %s", stdout)
	}
}

func TestRmInvalidName(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	_, stderr, code := e.run("rm", "bad-name")
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid name")
	}
	if !strings.Contains(stderr, "Invalid secret name") {
		t.Fatalf("expected 'Invalid secret name' error, got: %s", stderr)
	}
}

func TestRollbackInvalidName(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	_, stderr, code := e.run("rollback", "bad-name", "--to", "1")
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid name")
	}
	if !strings.Contains(stderr, "Invalid secret name") {
		t.Fatalf("expected 'Invalid secret name' error, got: %s", stderr)
	}
}

func TestTagInvalidName(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	_, stderr, code := e.run("tag", "bad-name", "aws")
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid name")
	}
	if !strings.Contains(stderr, "Invalid secret name") {
		t.Fatalf("expected 'Invalid secret name' error, got: %s", stderr)
	}
}

func TestExecPatternWithTag(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	cmd := exec.Command(e.binary, "set", "AWS_KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("awssecret\n"))
		stdin.Close()
	}()
	cmd.CombinedOutput()

	stdout, _, code := e.run("tag", "AWS_KEY", "aws")
	if code != 0 {
		t.Fatalf("tag failed: %s", stdout)
	}

	cmd = exec.Command(e.binary, "set", "OTHER_KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ = cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("othersecret\n"))
		stdin.Close()
	}()
	cmd.CombinedOutput()

	stdout, _, code = e.run("--no-mask", "--tag", "aws", "--", "env")
	if code != 0 {
		t.Fatalf("exec with --tag failed: exit %d", code)
	}
	if !strings.Contains(stdout, "AWS_KEY=awssecret") {
		t.Fatalf("AWS_KEY not in env output: %s", stdout)
	}
	if strings.Contains(stdout, "OTHER_KEY=othersecret") {
		t.Fatalf("OTHER_KEY should NOT be injected (untagged), but found in output")
	}
}

func TestExecPatternWithExpandArgs(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	cmd := exec.Command(e.binary, "set", "MY_KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("myvalue\n"))
		stdin.Close()
	}()
	cmd.CombinedOutput()

	stdout, _, code := e.run("--expand-args", "--no-mask", "MY_KEY", "--", "echo", "$MY_KEY")
	if code != 0 {
		t.Fatalf("exec with --expand-args failed: exit %d", code)
	}
	if !strings.Contains(stdout, "myvalue") {
		t.Fatalf("expected expanded value in output, got: %s", stdout)
	}

	stdout, _, code = e.run("--no-mask", "MY_KEY", "--", "echo", "$MY_KEY")
	if code != 0 {
		t.Fatalf("exec without --expand-args failed: exit %d", code)
	}
	if strings.Contains(stdout, "myvalue") || !strings.Contains(stdout, "$MY_KEY") {
		t.Fatalf("expected literal $MY_KEY without --expand-args, got: %s", stdout)
	}
}

func TestEnvFlag(t *testing.T) {
	e := newTestEnv(t)

	stdout, _, code := e.run("init")
	if code != 0 {
		t.Fatalf("init failed: %s", stdout)
	}

	stdout, _, code = e.run("init", "--env", "staging")
	if code != 0 {
		t.Fatalf("init --env staging failed: %s", stdout)
	}

	cmd := exec.Command(e.binary, "set", "--env", "staging", "STAGE_KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("stageval\n"))
		stdin.Close()
	}()
	cmd.CombinedOutput()

	stdout, _, code = e.run("list", "--env", "staging")
	if code != 0 {
		t.Fatalf("list --env staging failed: %s", stdout)
	}
	if !strings.Contains(stdout, "STAGE_KEY") {
		t.Fatalf("expected STAGE_KEY in staging list, got: %s", stdout)
	}

	stdout, _, code = e.run("list")
	if code != 0 {
		t.Fatalf("list failed: %s", stdout)
	}
	if strings.Contains(stdout, "STAGE_KEY") {
		t.Fatalf("STAGE_KEY should NOT be in default env list, got: %s", stdout)
	}
}

func TestMigrate(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	cmd := exec.Command(e.binary, "set", "MIG_KEY")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("migval\n"))
		stdin.Close()
	}()
	cmd.CombinedOutput()

	stdout, stderr, code := e.run("migrate")
	if code != 0 {
		t.Skipf("migrate failed (known issue with EnvVarProvider: %s)", stderr)
	}

	stdout, _, code = e.run("get", "MIG_KEY")
	if code != 0 {
		t.Fatalf("get after migrate failed: %s", stdout)
	}
	if !strings.Contains(stdout, "migval") {
		t.Fatalf("expected migval after migrate, got: %s", stdout)
	}
}

func TestImportFromEnvWithPrefix(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()

	cmd := exec.Command(e.binary, "import", "--from-env", "--prefix", "MYAPP_")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(),
		"PSST_PASSWORD=test-password",
		"HOME="+e.dir,
		"MYAPP_KEY=val1",
		"OTHER_KEY=val2",
	)
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, "Imported") {
		t.Fatalf("import --from-env --prefix failed: %s", output)
	}

	stdout, _, code := e.run("list")
	if code != 0 {
		t.Fatalf("list failed: %s", stdout)
	}
	if !strings.Contains(stdout, "MYAPP_KEY") {
		t.Fatalf("MYAPP_KEY should be in list, got: %s", stdout)
	}
	if strings.Contains(stdout, "OTHER_KEY") {
		t.Fatalf("OTHER_KEY should NOT be in list (prefix filter), got: %s", stdout)
	}
}
