# CLAUDE.md — psst

Profile for Claude (Anthropic) when working with the **psst** project.

## Primary Source

**Read `AGENTS.md` first.** It is the main entry point for all agents. All substantive rules live in `docs/rules/*.md`.

## Style & Behavior

- Respond concisely. Minimize output tokens while maintaining accuracy.
- When writing Go code: follow patterns from existing `internal/` packages.
- Use `fmt.Errorf("context: %w", err)` for error wrapping — no `errors.Wrap`.
- No comments unless explicitly requested.
- Use standard Go `testing` package — no testify, no mock frameworks.

## Rule Priorities

When rules conflict, follow this order:

1. `docs/rules/security.md` — always, no exceptions.
2. `docs/rules/architecture.md` — for structural decisions.
3. `docs/rules/codequality.md` — for code style and patterns.
4. `docs/rules/testing.md` — for test patterns.
5. `docs/rules/projectrules.md` — for project conventions.

## Before Making Changes

1. Read the relevant `docs/rules/*.md` modules per the lazy loading table in `AGENTS.md`.
2. Study existing code in the target package.
3. Write tests first if adding new functionality.
4. Run `make test` to verify.
