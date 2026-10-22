# Fuzzing

Two [cargo-fuzz](https://rust-fuzz.github.io/book/) targets:

- `evaluate` feeds arbitrary bytes to the public `vericto_engine::evaluate`
  entry point (the first byte picks the dialect);
- `policy` feeds an arbitrary CEL expression and an arbitrary SQL statement
  (split at the first NUL byte) to the business-policy checker, compiler and
  `vericto_engine::evaluate_with_context`, with a second, fixed policy that
  runs every facts helper.

Any panic, abort, stack overflow or timeout is a finding.

```bash
cargo install cargo-fuzz --locked
cargo +nightly fuzz run evaluate -- -max_total_time=600
cargo +nightly fuzz run policy -- -max_total_time=600
```

The scheduled workflow (`.github/workflows/fuzz.yml`) runs both targets for
10 minutes each every week. Because this repository is public, a crash input is not
printed in the log or uploaded as is: the job only reports that a crash
occurred. If the repository variable `FUZZ_ARTIFACT_AGE_RECIPIENT` holds an
[age](https://age-encryption.org) public key, the crash inputs are encrypted to
it and uploaded as a short-lived artifact; decrypt them locally with the
matching private key and reproduce with
`cargo +nightly fuzz run evaluate <file>`.

Report a crash privately, as described in [SECURITY.md](../SECURITY.md).
