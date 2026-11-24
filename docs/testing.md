# Testing

How Palisade is tested, which tests run where, and the conventions new tests follow.
[CONTRIBUTING.md](../CONTRIBUTING.md#testing-expectations) says what a change must come with, and
[ci.md](ci.md) lists every CI job.

## Kinds of test

| Kind | Where | Runs |
|---|---|---|
| Unit tests | `#[cfg(test)] mod tests` next to the code, or a `tests.rs` sibling module | Every `cargo test` / `cargo nextest run`, on every CI test runner |
| Integration tests | `crates/<crate>/tests/*.rs`, using only the crate's public API | Same |
| Property tests | `proptest`, in either of the above | Same |
| Golden-file tests | Expected output committed next to the test, regenerated on request | Same |
| Doctests | Examples in `///` comments | `cargo test --doc`, because nextest does not run them |
| Fuzz targets | `crates/<crate>/fuzz/`, cargo-fuzz (libFuzzer) | 60 s per target on every PR; 30 min per target weekly |
| Benchmarks | `crates/<crate>/benches/*.rs`, criterion | Built and run once in test mode on every PR; measured locally |
| Coverage | Unit, integration, property and golden-file tests, instrumented (not doctests, fuzzing or benchmarks) | Every PR, on Linux and Windows x64 |

## Running tests

```sh
cargo nextest run --workspace --all-features --locked   # the `default` profile
cargo nextest run --workspace --all-features --locked --profile ci
cargo test --workspace --all-features --locked --doc
cargo test --workspace --all-features --locked           # also works, without the JUnit report
```

`.config/nextest.toml` has two profiles:

- `default`: for local runs. No retries, and a test is reported as slow after 60 s.
- `ci`: the same, plus `fail-fast = false`, so one run reports every failure, and a JUnit report
  at `target/nextest/ci/junit.xml`. `cargo xtask test-summary` turns that report into the job
  summary ([ci.md](ci.md#test-reports)).

Neither profile retries. A test that passes only on a retry is flaky, and a flaky test in a
security product hides real failures, so it is fixed rather than retried.

The slowest tests are the 10,000-case property tests in `palisade-policy`, which take tens of
seconds in a debug build. Set `PROPTEST_CASES` to run fewer cases locally.

## Conventions

### Names

A test name says what is expected, as a sentence in snake case: what holds, or what happens in
which case. For example `hostile_descriptors_are_errors`, `every_truncation_of_a_rich_image` and
`huge_counts_do_not_overflow`. A reader of a failure should know what broke from the name alone.
Do not prefix names with `test_`.

### Determinism

- **No sleeps.** A test that waits for something uses a channel, a barrier or a mock clock. A
  `Clock` trait for code that reads the time arrives with the platform abstraction (#29). Until
  then, pass times in as values.
- **No network.** Unit and integration tests do not open sockets to anything outside the test,
  resolve names or download anything. Tests that need a real service, such as Postgres for the
  server (#126, #127), are marked and run only where that service is provided.
- **No dependence on the machine.** Tests do not read the user's home directory, environment or
  locale, or the system clock's time zone. Temporary files go in a fresh directory under
  `std::env::temp_dir()` or the target directory, and are removed afterwards.
- Randomness comes only from proptest, which reports a seed for every failure.

### Platforms

- Code and tests that only work on Windows are gated with `#[cfg(windows)]`, so the workspace
  builds and tests on every platform. CI runs the tests on Linux, macOS, Windows x64 and
  Windows ARM64.
- Tests that need administrator rights or a test VM are `#[ignore]`d, with a reason, and run in
  the VM harness (#26).
- Ignored tests that write files on request, such as the fuzz seed writers below, say so in
  their `#[ignore = "..."]` reason.

### Fixtures

- Fixtures are synthetic and built at test time where possible. `palisade-fileid` builds its PE
  images byte by byte (`crates/palisade-fileid/tests/common`), so no binaries are committed.
- Small committed fixtures (policy documents, PKCS#7 signatures) live in the crate's
  `tests/fixtures/`, each set with a note, or a script, that says how it was made.
- Never commit malware, antivirus test strings or third-party signed binaries
  ([responsible-use.md](responsible-use.md)). A generator for the full fixture corpus, and a
  check that `testdata/` holds only generated files, are planned in #25.

### Unwrap in tests

`clippy.toml` allows `unwrap` and `expect` inside `#[test]` functions. Helpers outside them need
`#![allow(clippy::unwrap_used)]` at the top of the test file, with a comment that says why.

## Property tests

Property tests use [`proptest`](https://docs.rs/proptest). Use them for invariants that must hold
for every input: parsers never panic and respect their limits, serialisation round-trips, and
matching agrees with a simpler reference.

- Failing cases are saved in `proptest-regressions/` next to the crate's sources. Commit those
  files. proptest replays the saved cases first on every run, so a fixed bug stays fixed.
- Prefer mutating valid inputs (flip, truncate, overwrite) over purely random bytes: they reach
  much deeper into a parser.
- The default case count is 256. Expensive properties set a smaller count with
  `ProptestConfig::with_cases`; important cheap ones set a larger one.

## Golden-file tests

A golden-file test compares generated output with a committed file. The convention is the one
`palisade-policy`'s JSON Schema test uses (`crates/palisade-policy/tests/schema.rs`):

- The test fails with a message that says how to regenerate the file.
- Setting `PALISADE_BLESS=1` makes the test rewrite the file instead of failing:
  `PALISADE_BLESS=1 cargo test -p palisade-policy --test schema`.
- A change to a golden file is reviewed in the PR like code. The diff shows what changed in the
  output.

A snapshot-testing library, and snapshots of decision traces, compiled policies, CLI output and
events, arrive with the code that produces that output (#25).

## Fuzzing

Every parser of untrusted input has a coverage-guided fuzz target. The targets live in a
separate cargo-fuzz workspace per crate (`crates/<crate>/fuzz/`), so normal builds never compile
them, and only they need a nightly toolchain. There are two projects:

- `crates/palisade-fileid/fuzz`, with ten targets: `pe_parse`, `version_info_parse`,
  `authenticode_ranges`, `authenticode_pkcs7`, `fsctx_parse`, `x509_chain`, `timestamp_crl`,
  `fuzz_ctl`, `fuzz_classify` and `script_sig`.
- `crates/palisade-proto/fuzz`, with one target: `trust_set_decode`.

Target names are unique across projects, so `--target` names one without its project. Each fuzz
workspace has its own committed `Cargo.lock`. Dependabot keeps it up to date, cargo-deny checks it against the root `deny.toml` on every PR and daily, and
`cargo xtask audit` runs cargo-audit over it. cargo-vet covers only the root workspace, so a
fuzz-only dependency is reviewed in its PR instead
([dependencies.md](dependencies.md)). The fuzz crates are never shipped.

One command builds every target of every project, seeds its corpus from the synthetic test fixtures, and runs it:

```sh
rustup toolchain install nightly-2026-11-20 --profile minimal
cargo install --locked cargo-fuzz@0.13.2
cargo xtask fuzz                         # 60 s per target, as on a PR
cargo xtask fuzz --seconds 1800 --target pe_parse
```

The nightly is pinned by date in `xtask/src/fuzz.rs`, so a new nightly cannot break CI. The
lockfile is checked with `cargo fetch --locked` on that nightly, and the build and runs are then
offline, so they cannot download anything or re-resolve the lockfile. The
corpus and any findings go to `target/fuzz-smoke/<target>/`. Each target runs with a 10 s limit
per input and a 2 GiB memory limit, so hangs and runaway allocation count as findings too.

- **On every PR**, the `fuzz` job in `ci.yml` runs `cargo xtask fuzz`.
- **Every week**, `fuzz.yml` runs each target for 30 minutes, as one job per target. If any
  fails, it opens an `area:security` issue, or comments on the open one.

A finding fails the job. The job summary lists each target's result and, for each failing input
up to 64 KiB, the input itself as base64 with the command that reproduces it. That stands in for
an artefact upload, which would need an action outside the allowlist ([ci.md](ci.md)). To fix a
finding:

1. Reproduce it locally with the command from the job summary.
2. Fix the parser.
3. Add the input as a regression test in the crate's normal tests, so it runs on every platform
   on every PR, not only under the fuzzer.

`xtask/src/fuzz.rs` lists every fuzz project and target. Its tests fail if a target is missing
from the list, from a project's `Cargo.toml` or from `fuzz.yml`'s matrix, if two projects use the
same target name, if a `crates/*/fuzz` project is not listed, or if a project has no committed
lockfile. To add a target:

1. Add the target to `fuzz_targets/` and as a `[[bin]]` in the project's `Cargo.toml`.
2. Add it to `PROJECTS` in `xtask/src/fuzz.rs`, with its dictionary and the ignored tests that
   write its seed inputs (they read the output directory from `PALISADE_FUZZ_SEED_DIR`).
3. Add it to the matrix in `.github/workflows/fuzz.yml`.

For a new crate's fuzz project, also add it to `PROJECTS` with the package whose tests write its
seeds, commit its `Cargo.lock` (and keep `Cargo.lock` out of its `.gitignore`), add it to
`.github/dependabot.yml`, and add its cargo-deny step to the `deps` job in `ci.yml`, to
`audit.yml` and to `xtask/src/ci.rs`. The tests in `xtask/src/fuzz.rs` fail
until all of these are in place. A seed writer that writes nothing fails the run, because libtest
passes when `--exact` matches no test.

## Coverage

The `coverage` job in `ci.yml` runs the nextest suite under
[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov), on ubuntu-latest and windows-latest.
`cargo xtask coverage-summary` then writes a table to the job summary page: line, function and
region coverage for each crate, and the total. The instrumentation needs `llvm-tools-preview`,
which `rust-toolchain.toml` installs.

Coverage is reported, not enforced. The initial targets are 80% line coverage for
`palisade-policy` and `palisade-fileid` (#25). A crate below its target gets a warning
annotation on the run, and the job still passes. Uploading the full report as an artefact, and a
no-decrease rule for `palisade-policy`, are deferred (#25).

To see the report locally:

```sh
cargo install --locked cargo-llvm-cov@0.9.2
cargo llvm-cov nextest --workspace --all-features --locked --profile ci \
  --json --summary-only --output-path target/llvm-cov-summary.json
cargo xtask coverage-summary local target/llvm-cov-summary.json
cargo llvm-cov report --html --open      # line-by-line, from the same run
```

## Benchmarks

Benchmarks use [criterion](https://docs.rs/criterion), in `crates/<crate>/benches/`:

| Crate | Bench | What it measures |
|---|---|---|
| `palisade-policy` | `criterion_eval` | One compiled criterion against an object's facts: hash, 25-value text, path wildcard, regex and version range |
| `palisade-fileid` | `hash_and_parse` | Flat hashing of 1 MiB with each algorithm set, streamed hashing, PE parsing (full and metadata-only) and the Authenticode hash |

Run them locally, on a quiet machine:

```sh
cargo bench -p palisade-policy --bench criterion_eval
cargo bench -p palisade-fileid --bench hash_and_parse
cargo bench -p palisade-policy --bench criterion_eval -- --save-baseline before   # then, after a change:
cargo bench -p palisade-policy --bench criterion_eval -- --baseline before
```

The `bench` job in CI builds every bench and runs each benchmark once in test mode
(`cargo test --bench <name>`). That catches benches that no longer build or that panic, but it
measures nothing. Shared hosted runners vary too much from run to run for their timings to be
compared. A test in `xtask/src/ci.rs` fails if a `benches/*.rs` file is missing from the job.

criterion 0.7 was chosen because later releases needed a newer Rust than the MSRV of the time
(1.85), and the `msrv` job builds every target, including benches. The MSRV is now 1.94
([workspace.md](workspace.md#toolchain-and-msrv)); moving to a newer criterion is a separate
change. Its plotting and parallel features are off.

Benchmarks over whole policies (100 to 100k rules), 100 MB and 1 GB files and bundle loading,
the regression comparison against `main`, and the performance-budget test, arrive with the code
they measure (#25).
