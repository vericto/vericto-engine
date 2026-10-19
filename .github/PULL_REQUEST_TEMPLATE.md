## What does this PR change?

<!-- A clear, concise description of the change. -->

## Why?

<!-- Context: a missed destructive pattern, a parser bug, a new dialect, perf. -->

## Type of change

- [ ] New rule
- [ ] Parser / dialect fix
- [ ] Performance improvement
- [ ] Bug fix
- [ ] Documentation

## Tests

- [ ] Added a "must be blocked" test (positive case)
- [ ] Added a "must be allowed" test (false-positive guard)
- [ ] `cargo test` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo fmt --check` passes

## Checklist

- [ ] No `unwrap()` / `expect()` on runtime paths
- [ ] Public functions documented with `///`
- [ ] Commits follow Conventional Commits
- [ ] I have signed the Vericto Contributor License Agreement in `CLA.md` (on your first pull request, comment `I have read the CLA Document and I hereby sign the CLA`; comment `recheck` if the `CLA` check does not rerun)
- [ ] Rule documented in `README.md` (if adding a rule)
