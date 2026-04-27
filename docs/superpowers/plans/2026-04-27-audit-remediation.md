# Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 9 audit findings (3 HIGH, 5 MEDIUM, 4 LOW) — security hardening, bug fixes, test coverage.

**Architecture:** Targeted fixes in vault, runner, cli, output packages. Each task is independently committable. No new dependencies.

**Tech Stack:** Go 1.26, standard library + existing deps (cobra, sqlite, argon2, keyring).

---

## File Structure

| Action | File | Purpose |
|--------|------|---------|
| Modify | `internal/vault/secrets.go` | H1: zero key copies |
| Modify | `internal/vault/unlock.go` | H3: lazy-load secrets; M3: handle SetMeta errors |
| Modify | `internal/vault/tags.go` | M2: refactor GetSecretsByTagValues |
| Modify | `internal/runner/runner.go` | M4: use crypto.ZeroBytes |
| Modify | `Makefile` | H2: add -race |
| Modify | `internal/cli/args.go` | M5: unify flag parsing |
| Modify | `internal/cli/root.go` | M5: extract flag definitions |
| Modify | `internal/output/output_test.go` | L3: add missing tests |
| Modify | `tests/integration_test.go` | L4: add missing integration tests |

---

### Task 1: H1 — Zero key copies in GetSecret and GetAllSecrets

**Files:**
- Modify: `internal/vault/secrets.go:63` and `internal/vault/secrets.go:123`

- [ ] **Step 1: Add defer crypto.ZeroBytes(key) to GetSecret**

In `internal/vault/secrets.go`, add the defer after the `copyKey` call in `GetSecret`:

```go
func (v *Vault) GetSecret(ctx context.Context, name string) (*Secret, error) {
	key, err := v.copyKey()
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)
```

- [ ] **Step 2: Add defer crypto.ZeroBytes(key) to GetAllSecrets**

In the same file, add the defer in `GetAllSecrets`:

```go
func (v *Vault) GetAllSecrets(ctx context.Context) (map[string][]byte, error) {
	key, err := v.copyKey()
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/vault/ -v -run TestSetGetSecret`
Run: `go test ./internal/vault/ -v -run TestGetAllSecrets`
Expected: PASS

- [ ] **Step 4: Run full test suite**

Run: `go test ./... -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/secrets.go
git commit -m "fix: zero key copies after GetSecret and GetAllSecrets"
```

---

### Task 2: H2 — Add -race to make test

**Files:**
- Modify: `Makefile:19`

- [ ] **Step 1: Update Makefile test target**

Change line 19 of `Makefile` from:

```
	go test ./... -v
```

to:

```
	go test -race ./... -v
```

- [ ] **Step 2: Run make test to verify**

Run: `make test`
Expected: All PASS (may be slower due to race detector)

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "fix: enable race detector in make test"
```

---

### Task 3: H3 — Lazy-load secrets in Unlock

**Files:**
- Modify: `internal/vault/unlock.go:64-91`

- [ ] **Step 1: Write the test for unlock without loading all secrets**

Add a test in `internal/vault/vault_test.go` that verifies unlock works when vault has verify_data but no secrets:

```go
func TestUnlock_WithVerifyData_NoSecrets(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	if err := v.Unlock(ctx); err != nil {
		t.Fatal(err)
	}

	sec, err := v.GetSecret(ctx, "NONEXISTENT")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
	_ = sec
}
```

- [ ] **Step 2: Run test to verify it passes (verify_data path already works)**

Run: `go test ./internal/vault/ -v -run TestUnlock_WithVerifyData_NoSecrets`
Expected: PASS

- [ ] **Step 3: Restructure Unlock to lazy-load**

In `internal/vault/unlock.go`, replace the block from line 64 to line 91. The current code:

```go
	all, verifyErr := v.store.GetAllSecrets(ctx)
	if verifyErr != nil {
		return fmt.Errorf("verify vault: %w", verifyErr)
	}

	verifyIV, ivErr := v.store.GetMeta(ctx, "verify_iv")
	verifyData, dataErr := v.store.GetMeta(ctx, "verify_data")

	verified := false
	if ivErr == nil && dataErr == nil && verifyIV != "" && verifyData != "" {
		ivBytes, ivDecodeErr := base64.StdEncoding.DecodeString(verifyIV)
		if ivDecodeErr != nil {
			return fmt.Errorf("decode verify_iv: %w", ivDecodeErr)
		}
		dataBytes, dataDecodeErr := base64.StdEncoding.DecodeString(verifyData)
		if dataDecodeErr != nil {
			return fmt.Errorf("decode verify_data: %w", dataDecodeErr)
		}
		if _, decErr := v.enc.Decrypt(dataBytes, ivBytes, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		verified = true
	} else if len(all) > 0 {
		if _, decErr := v.enc.Decrypt(all[0].EncryptedValue, all[0].IV, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		verified = true
	}
```

Replace with:

```go
	verified := false

	verifyIV, ivErr := v.store.GetMeta(ctx, "verify_iv")
	verifyData, dataErr := v.store.GetMeta(ctx, "verify_data")

	if ivErr == nil && dataErr == nil && verifyIV != "" && verifyData != "" {
		ivBytes, ivDecodeErr := base64.StdEncoding.DecodeString(verifyIV)
		if ivDecodeErr != nil {
			return fmt.Errorf("decode verify_iv: %w", ivDecodeErr)
		}
		dataBytes, dataDecodeErr := base64.StdEncoding.DecodeString(verifyData)
		if dataDecodeErr != nil {
			return fmt.Errorf("decode verify_data: %w", dataDecodeErr)
		}
		if _, decErr := v.enc.Decrypt(dataBytes, ivBytes, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		verified = true
	} else {
		all, verifyErr := v.store.GetAllSecrets(ctx)
		if verifyErr != nil {
			return fmt.Errorf("verify vault: %w", verifyErr)
		}
		if len(all) > 0 {
			if _, decErr := v.enc.Decrypt(all[0].EncryptedValue, all[0].IV, key); decErr != nil {
				return v.failUnlock(ctx, key)
			}
			verified = true
		}
	}
```

- [ ] **Step 4: Run full vault tests**

Run: `go test ./internal/vault/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/unlock.go
git commit -m "refactor: lazy-load secrets in Unlock only when verify_data absent"
```

---

### Task 4: M3 — Handle SetMeta errors in failUnlock

**Files:**
- Modify: `internal/vault/unlock.go:105-126`

- [ ] **Step 1: Update failUnlock to propagate SetMeta errors**

Replace the `failUnlock` function in `internal/vault/unlock.go` (lines 105-126) with:

```go
func (v *Vault) failUnlock(ctx context.Context, key []byte) error {
	crypto.ZeroBytes(key)
	attempts, incErr := v.store.IncrementMetaInt(ctx, metaUnlockAttempts, 1)
	if incErr != nil {
		return fmt.Errorf("authentication failed (rate-limit write error: %w)", incErr)
	}
	if attempts >= maxUnlockAttempts {
		cycle := 0
		if cycleStr, cycleErr := v.store.GetMeta(ctx, metaUnlockCycle); cycleErr == nil {
			if n, e := strconv.Atoi(cycleStr); e == nil {
				cycle = n
			}
		}

		lockDuration := min(
			time.Duration(unlockDelayBaseMs)*time.Millisecond*time.Duration(1<<uint(cycle)),
			maxLockDuration,
		)
		lockedUntil := time.Now().Add(lockDuration)
		if metaErr := v.store.SetMeta(ctx, metaUnlockLockedUntil, lockedUntil.Format(time.RFC3339)); metaErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to persist lock state: %v\n", metaErr)
		}
		_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
		_ = v.store.SetMeta(ctx, metaUnlockCycle, strconv.Itoa(cycle+1))
	}
	return errors.New("authentication failed")
}
```

Key changes:
- `IncrementMetaInt` error is checked and returned
- `SetMeta` for `lockedUntil` logs warning on failure (critical for rate-limiting)
- Less critical `SetMeta` calls (`unlock_attempts` reset, `unlock_cycle` increment) remain silently ignored — these are best-effort

- [ ] **Step 2: Run full vault tests**

Run: `go test ./internal/vault/ -v -run TestUnlock`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add internal/vault/unlock.go
git commit -m "fix: propagate rate-limit metadata errors in failUnlock"
```

---

### Task 5: M2 — Refactor GetSecretsByTagValues to avoid N+1

**Files:**
- Modify: `internal/vault/tags.go:90-104`

- [ ] **Step 1: Write the test**

Add a test in `internal/vault/vault_test.go` to verify `GetSecretsByTagValues` returns correct values:

```go
func TestGetSecretsByTagValues(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "KEY_A", []byte("val_a"), []string{"aws"})
	v.SetSecret(ctx, "KEY_B", []byte("val_b"), []string{"aws", "prod"})
	v.SetSecret(ctx, "KEY_C", []byte("val_c"), []string{"gcp"})

	result, err := v.GetSecretsByTagValues(ctx, []string{"aws"})
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(result))
	}
	if string(result["KEY_A"]) != "val_a" {
		t.Fatalf("KEY_A = %q, want %q", string(result["KEY_A"]), "val_a")
	}
	if string(result["KEY_B"]) != "val_b" {
		t.Fatalf("KEY_B = %q, want %q", string(result["KEY_B"]), "val_b")
	}
	if _, ok := result["KEY_C"]; ok {
		t.Fatal("KEY_C should not be in results")
	}
}
```

- [ ] **Step 2: Run test to verify it passes (current implementation works)**

Run: `go test ./internal/vault/ -v -run TestGetSecretsByTagValues`
Expected: PASS

- [ ] **Step 3: Refactor GetSecretsByTagValues**

Replace `GetSecretsByTagValues` in `internal/vault/tags.go` (lines 90-104) with:

```go
func (v *Vault) GetSecretsByTagValues(ctx context.Context, tags []string) (map[string][]byte, error) {
	names, err := v.GetSecretNamesByTags(ctx, tags)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return map[string][]byte{}, nil
	}

	all, err := v.GetAllSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("get secrets: %w", err)
	}

	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}

	result := make(map[string][]byte, len(names))
	for name, val := range all {
		if nameSet[name] {
			result[name] = val
		}
	}
	return result, nil
}
```

Benefits: one `GetAllSecrets` call (one key copy, one store query) instead of N calls.

- [ ] **Step 4: Run test to verify refactored version passes**

Run: `go test ./internal/vault/ -v -run TestGetSecretsByTagValues`
Expected: PASS

- [ ] **Step 5: Run full vault tests**

Run: `go test ./internal/vault/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/vault/tags.go internal/vault/vault_test.go
git commit -m "refactor: GetSecretsByTagValues uses single GetAllSecrets instead of N+1"
```

---

### Task 6: M4 — Deduplicate zeroBytes

**Files:**
- Modify: `internal/runner/runner.go:199-203` and all call sites in runner package

- [ ] **Step 1: Replace runner.zeroBytes with crypto.ZeroBytes**

In `internal/runner/runner.go`:

Add import:
```go
"github.com/aatumaykin/psst/internal/crypto"
```

Replace all calls to `zeroBytes(...)` with `crypto.ZeroBytes(...)` in `runner.go`:
- Line 113: `zeroBytes(secretValues[i])` → `crypto.ZeroBytes(secretValues[i])`
- Line 143: `zeroBytes(tail)` → `crypto.ZeroBytes(tail)`
- Line 150: `zeroBytes(data)` → `crypto.ZeroBytes(data)`
- Line 154: `zeroBytes(masked)` → `crypto.ZeroBytes(masked)`
- Line 163: `zeroBytes(masked)` → `crypto.ZeroBytes(masked)`

Then delete the local `zeroBytes` function (lines 199-203):

```go
// DELETE this function:
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
```

- [ ] **Step 2: Run runner tests**

Run: `go test ./internal/runner/ -v`
Expected: All PASS

- [ ] **Step 3: Run full test suite**

Run: `go test ./... -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add internal/runner/runner.go
git commit -m "refactor: replace runner.zeroBytes with crypto.ZeroBytes"
```

---

### Task 7: M5 — Unify flag parsing

**Files:**
- Modify: `internal/cli/root.go`
- Modify: `internal/cli/args.go`

- [ ] **Step 1: Define flag metadata struct in args.go**

Add to `internal/cli/args.go` after the imports:

```go
type flagDef struct {
	Name    string
	Short   string
	HasValue bool
}

var globalFlags = []flagDef{
	{Name: "--json", Short: ""},
	{Name: "--quiet", Short: "-q"},
	{Name: "--global", Short: "-g"},
	{Name: "--env", HasValue: true},
	{Name: "--tag", HasValue: true},
}

func isKnownFlag(arg string) bool {
	for _, f := range globalFlags {
		if arg == f.Name || (f.Short != "" && arg == f.Short) {
			return true
		}
		if f.HasValue && strings.HasPrefix(arg, f.Name+"=") {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Rewrite parseGlobalFlagsFromArgs using the struct**

Replace `parseGlobalFlagsFromArgs` in `internal/cli/args.go`:

```go
func parseGlobalFlagsFromArgs(args []string) (bool, bool, bool, string, []string) {
	var jsonOut, quiet, global bool
	var env string
	var tags []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--quiet", "-q":
			quiet = true
		case "--global", "-g":
			global = true
		case "--env":
			i++
			if i < len(args) {
				env = args[i]
			}
		case "--tag":
			i++
			if i < len(args) {
				tags = append(tags, args[i])
			}
		default:
			if v, found := strings.CutPrefix(args[i], "--env="); found {
				env = v
				continue
			}
			if v, found := strings.CutPrefix(args[i], "--tag="); found {
				tags = append(tags, v)
			}
		}
	}
	if os.Getenv("PSST_GLOBAL") == "1" {
		global = true
	}
	if env == "" {
		env = os.Getenv("PSST_ENV")
	}
	return jsonOut, quiet, global, env, tags
}
```

Note: function body stays the same — the `globalFlags` slice is used by `filterSecretNames` and `isKnownFlag`.

- [ ] **Step 3: Rewrite filterSecretNames using isKnownFlag**

Replace `filterSecretNames` in `internal/cli/args.go`:

```go
func filterSecretNames(args []string) []string {
	valueArgs := map[int]bool{}
	for i := 0; i < len(args); i++ {
		for _, f := range globalFlags {
			if !f.HasValue {
				continue
			}
			if args[i] == f.Name && i+1 < len(args) {
				valueArgs[i] = true
				valueArgs[i+1] = true
				i++
				break
			}
			if strings.HasPrefix(args[i], f.Name+"=") {
				valueArgs[i] = true
				break
			}
		}
	}

	extraFlags := map[string]bool{"--no-mask": true, "--expand-args": true}

	var names []string
	for i, a := range args {
		if isKnownFlag(a) || extraFlags[a] || valueArgs[i] {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	return names
}
```

- [ ] **Step 4: Run args tests**

Run: `go test ./internal/cli/ -v -run TestParse`
Expected: All PASS

- [ ] **Step 5: Run full test suite**

Run: `go test ./... -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/cli/args.go
git commit -m "refactor: extract flag definitions into shared globalFlags struct"
```

---

### Task 8: L3 — Add missing output tests

**Files:**
- Modify: `internal/output/output_test.go`

- [ ] **Step 1: Add ScanResults tests**

Append to `internal/output/output_test.go`:

```go
func TestScanResultsEmpty(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.ScanResults(nil)
	if !strings.Contains(buf.String(), "No secrets found") {
		t.Fatalf("expected no-secrets message, got: %s", buf.String())
	}
}

func TestScanResultsHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.ScanResults([]ScanMatch{
		{File: "config.yaml", Line: 5, SecretName: "API_KEY"},
	})
	if !strings.Contains(buf.String(), "config.yaml:5") {
		t.Fatalf("expected file:line in output, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "API_KEY") {
		t.Fatalf("expected secret name in output, got: %s", buf.String())
	}
}

func TestScanResultsJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}
	f.ScanResults([]ScanMatch{
		{File: "config.yaml", Line: 5, SecretName: "API_KEY"},
	})
	if !strings.Contains(buf.String(), `"file"`) {
		t.Fatalf("expected JSON output, got: %s", buf.String())
	}
}
```

- [ ] **Step 2: Add EnvList / EnvListWriter tests**

```go
func TestEnvListHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.EnvList(map[string]string{"KEY": "value", "PATH_KEY": `path with spaces`})
	output := buf.String()
	if !strings.Contains(output, "KEY=value") {
		t.Fatalf("expected KEY=value in output, got: %s", output)
	}
	if !strings.Contains(output, `"path with spaces"`) {
		t.Fatalf("expected quoted value, got: %s", output)
	}
}

func TestEnvListJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}
	f.EnvList(map[string]string{"KEY": "value"})
	if !strings.Contains(buf.String(), `"KEY"`) {
		t.Fatalf("expected JSON output, got: %s", buf.String())
	}
}

func TestEnvListWriter(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{}
	f.EnvListWriter(map[string]string{"A": "1", "B": "2"}, &buf)
	if !strings.Contains(buf.String(), "A=1") || !strings.Contains(buf.String(), "B=2") {
		t.Fatalf("expected both entries, got: %s", buf.String())
	}
}
```

- [ ] **Step 3: Add EnvironmentList test**

```go
func TestEnvironmentListHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.EnvironmentList([]string{"prod", "staging"})
	if !strings.Contains(buf.String(), "prod") || !strings.Contains(buf.String(), "staging") {
		t.Fatalf("expected env names in output, got: %s", buf.String())
	}
}

func TestEnvironmentListEmpty(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.EnvironmentList(nil)
	if !strings.Contains(buf.String(), "No environments") {
		t.Fatalf("expected empty message, got: %s", buf.String())
	}
}
```

- [ ] **Step 4: Add VersionInfo test**

```go
func TestVersionInfoHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.VersionInfo(VersionData{
		Version: "1.0.0", Commit: "abc123", Date: "2025-01-01",
		GoVersion: "go1.26", OSArch: "linux/amd64",
	})
	if !strings.Contains(buf.String(), "psst 1.0.0") {
		t.Fatalf("expected version in output, got: %s", buf.String())
	}
}

func TestVersionInfoQuiet(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{quiet: true, stdout: &buf, stderr: &buf}
	f.VersionInfo(VersionData{Version: "1.0.0"})
	if !strings.Contains(buf.String(), "1.0.0") {
		t.Fatalf("quiet mode should output version, got: %s", buf.String())
	}
	if strings.Contains(buf.String(), "commit") {
		t.Fatalf("quiet mode should not output details, got: %s", buf.String())
	}
}

func TestVersionInfoJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}
	f.VersionInfo(VersionData{Version: "1.0.0", Commit: "abc123"})
	if !strings.Contains(buf.String(), `"version"`) {
		t.Fatalf("expected JSON output, got: %s", buf.String())
	}
}
```

- [ ] **Step 5: Add Print test**

```go
func TestPrint(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.Print("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Fatalf("expected message, got: %s", buf.String())
	}
}

func TestPrintQuiet(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{quiet: true, stdout: &buf, stderr: &buf}
	f.Print("hello")
	if len(buf.String()) > 0 {
		t.Fatalf("quiet should produce no output, got: %s", buf.String())
	}
}
```

- [ ] **Step 6: Run output tests**

Run: `go test ./internal/output/ -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add internal/output/output_test.go
git commit -m "test: add coverage for ScanResults, EnvList, VersionInfo, Print"
```

---

### Task 9: L4 — Add integration tests for exec-pattern and flags

**Files:**
- Modify: `tests/integration_test.go`

- [ ] **Step 1: Add test for exec-pattern with --tag**

Append to `tests/integration_test.go`:

```go
func TestExecPatternWithTag(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun("init")
	env.setPassword("test-password")
	env.mustRun("set", "API_KEY", stdin("secret123"))
	env.mustRun("tag", "API_KEY", "--tag", "aws")

	output := env.mustRun("--tag", "aws", "--", "env")
	if !strings.Contains(output, "API_KEY=secret123") {
		t.Fatalf("expected API_KEY in env output, got: %s", output)
	}
}
```

- [ ] **Step 2: Add test for --expand-args**

```go
func TestExecPatternWithExpandArgs(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun("init")
	env.setPassword("test-password")
	env.mustRun("set", "API_KEY", stdin("secret123"))

	output := env.mustRun("--expand-args", "API_KEY", "--", "echo", "$API_KEY")
	if !strings.Contains(output, "secret123") {
		t.Fatalf("expected expanded secret in output, got: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("expected masked output, got: %s", output)
	}
}
```

- [ ] **Step 3: Add test for --env flag**

```go
func TestEnvFlag(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun("init", "--env", "staging")
	env.setPassword("test-password")
	env.mustRun("--env", "staging", "set", "DB_HOST", stdin("db.example.com"))

	output := env.mustRun("--env", "staging", "list")
	if !strings.Contains(output, "DB_HOST") {
		t.Fatalf("expected DB_HOST in list, got: %s", output)
	}
}
```

- [ ] **Step 4: Add test for migrate**

```go
func TestMigrate(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun("init")
	env.setPassword("test-password")
	env.mustRun("set", "KEY", stdin("val"))

	output := env.mustRun("migrate")
	if !strings.Contains(output, "migrated") && !strings.Contains(output, "already") {
		t.Fatalf("expected migrate output, got: %s", output)
	}

	val := env.mustRun("get", "KEY")
	if !strings.Contains(val, "val") {
		t.Fatalf("secret should survive migration, got: %s", val)
	}
}
```

- [ ] **Step 5: Run integration tests**

Run: `go test ./tests/ -v -run TestExecPatternWithTag`
Run: `go test ./tests/ -v -run TestExecPatternWithExpandArgs`
Run: `go test ./tests/ -v -run TestEnvFlag`
Run: `go test ./tests/ -v -run TestMigrate`
Expected: All PASS

Note: if `newTestEnv` or helper methods differ from what's shown, adapt to match the existing test patterns in `integration_test.go`.

- [ ] **Step 6: Commit**

```bash
git add tests/integration_test.go
git commit -m "test: add integration tests for exec-pattern with --tag, --expand-args, --env, migrate"
```

---

## Final Verification

- [ ] **Run full test suite with race detector**

Run: `make test`
Expected: All PASS

- [ ] **Run linter**

Run: `make lint`
Expected: No errors

- [ ] **Verify no regressions**

Run: `make build && ./psst version`
Expected: Version info printed
