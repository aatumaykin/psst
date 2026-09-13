# AGENTS.md — psst

Main entry point for all AI agents working with the **psst** project.

## Project Summary

**psst** is a secrets manager for AI agents. Written in Go. CLI-only tool that injects secrets into subprocess environments. Agents orchestrate, psst handles the secrets — the agent never sees secret values.

## Role

You are an assistant developer for this project. Your tasks include writing code, tests, documentation, and reviewing changes. Follow the rules described in `docs/rules/*.md`.

## Rules Loading Strategy (Lazy Loading)

Read **only the modules you need** for the current task:

| Task | Read these modules |
|------|--------------------|
| **Any task** | `docs/rules/security.md` + `docs/rules/projectrules.md` |
| Architecture / refactoring | `docs/rules/architecture.md` |
| Writing or editing code | `docs/rules/codequality.md` |
| Writing or editing tests | `docs/rules/testing.md` |
| Adding new CLI commands | `docs/rules/architecture.md` + `docs/rules/codequality.md` |
| Changing encryption/storage | `docs/rules/architecture.md` + `docs/rules/security.md` |

**Priority:** `security.md` > `architecture.md` > `codequality.md` > `testing.md` > `projectrules.md`.

## Mandatory Rules

1. **Security first.** This is a secrets manager. Any change that leaks secret values is a critical bug. Always read `docs/rules/security.md` before making changes.
2. **Run tests before committing.** `make test` must pass.
3. **Follow existing patterns.** Study `internal/` packages before writing new code.
4. **No new dependencies** without justification.
5. **Conventional commits.** `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`.
6. **No comments** unless asked.

## Quick Reference

```
make build          # Build binary
make test           # Run tests
make clean          # Remove binary
```

Module path: `github.com/aatumaykin/psst`

## Commands (18 root + exec pattern)

`init`, `set`, `get`, `list`, `rm`, `run`, `export`, `import`, `history`, `rollback`, `tag`, `untag`, `scan`, `migrate`, `completion`, `version`, `list-envs`, `update` (with `check`/`install` sub-commands).
