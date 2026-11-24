//! `cargo xtask fuzz [--seconds N]`: builds every cargo-fuzz target, seeds
//! its corpus from the synthetic test fixtures, and runs it for `N` seconds
//! (default [`DEFAULT_SECONDS`]).
//!
//! CI runs it on every pull request (the `fuzz` job in `ci.yml`), and
//! `fuzz.yml` runs it weekly with a longer time per target. Every target
//! runs even after one fails. The results go to the job summary, including
//! each crashing input as base64 so it can be reproduced without an
//! artefact upload.
//!
//! [`PROJECTS`] lists every fuzz project and target. Unit tests compare it
//! with each project's `Cargo.toml` and with the `crates/*/fuzz` directories,
//! so a new target or project cannot be left out of CI.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The nightly toolchain the fuzz targets build with. libFuzzer and the
/// sanitizers need nightly; the date pins it, so CI does not break when a
/// new nightly does. `ci.yml` and `fuzz.yml` install exactly this.
pub const TOOLCHAIN: &str = "nightly-2026-11-20";

/// The cargo-fuzz version CI installs.
pub const CARGO_FUZZ: &str = "cargo-fuzz@0.13.2";

/// Seconds per target when `--seconds` is not given.
pub const DEFAULT_SECONDS: u32 = 60;

/// The largest `--seconds` accepted: one hour per target.
pub const MAX_SECONDS: u32 = 3600;

/// libFuzzer's per-input timeout, in seconds. An input that takes longer is
/// reported as a hang (a `timeout-*` artefact).
const INPUT_TIMEOUT_SECONDS: u32 = 10;

/// libFuzzer's memory limit, in MiB. Going over it is reported as an
/// out-of-memory finding.
const RSS_LIMIT_MB: u32 = 2048;

/// Crashing inputs up to this size are written into the job summary.
const MAX_INLINE_ARTIFACT: usize = 64 * 1024;

/// A cargo-fuzz project: a `fuzz/` directory with its own workspace.
#[derive(Debug)]
pub struct Project {
    /// The project directory, relative to the repository root.
    pub dir: &'static str,
    /// The workspace package whose tests write the seed inputs.
    pub package: &'static str,
    /// Every `[[bin]]` target of the project.
    pub targets: &'static [Target],
}

/// One fuzz target.
#[derive(Debug)]
pub struct Target {
    pub name: &'static str,
    /// A libFuzzer dictionary, relative to the project directory.
    pub dict: Option<&'static str>,
    /// Ignored tests that write seed inputs into `PALISADE_FUZZ_SEED_DIR`.
    pub seeds: &'static [Seed],
}

/// An ignored test, in `<package>/tests/<test>.rs`, that writes seed inputs.
#[derive(Debug)]
pub struct Seed {
    pub test: &'static str,
    pub name: &'static str,
}

const PE_SEEDS: Seed = Seed {
    test: "properties",
    name: "write_fuzz_seeds",
};
const PKCS7_SEEDS: Seed = Seed {
    test: "signature",
    name: "write_pkcs7_fuzz_seeds",
};
const FSCTX_SEEDS: Seed = Seed {
    test: "fsctx",
    name: "write_fsctx_fuzz_seeds",
};
const X509_SEEDS: Seed = Seed {
    test: "chain",
    name: "write_x509_chain_fuzz_seeds",
};
const TIMESTAMP_SEEDS: Seed = Seed {
    test: "validity",
    name: "write_timestamp_fuzz_seeds",
};
const CTL_SEEDS: Seed = Seed {
    test: "catalog",
    name: "write_ctl_fuzz_seeds",
};
const FILETYPE_SEEDS: Seed = Seed {
    test: "filetype",
    name: "write_fuzz_seeds",
};
const SCRIPT_SEEDS: Seed = Seed {
    test: "script",
    name: "write_script_fuzz_seeds",
};
const TRUST_SET_SEEDS: Seed = Seed {
    test: "trust_set",
    name: "write_trust_set_fuzz_seeds",
};

/// Every fuzz project in the repository.
pub const PROJECTS: &[Project] = &[
    Project {
        dir: "crates/palisade-fileid/fuzz",
        package: "palisade-fileid",
        targets: &[
            Target {
                name: "pe_parse",
                dict: Some("pe.dict"),
                seeds: &[PE_SEEDS],
            },
            Target {
                name: "version_info_parse",
                dict: Some("pe.dict"),
                seeds: &[PE_SEEDS],
            },
            Target {
                name: "authenticode_ranges",
                dict: Some("pe.dict"),
                seeds: &[PE_SEEDS],
            },
            Target {
                name: "authenticode_pkcs7",
                dict: Some("pkcs7.dict"),
                seeds: &[PKCS7_SEEDS],
            },
            Target {
                name: "fsctx_parse",
                dict: None,
                seeds: &[FSCTX_SEEDS],
            },
            Target {
                name: "x509_chain",
                dict: Some("pkcs7.dict"),
                seeds: &[X509_SEEDS],
            },
            Target {
                name: "timestamp_crl",
                dict: Some("pkcs7.dict"),
                seeds: &[TIMESTAMP_SEEDS],
            },
            Target {
                name: "fuzz_ctl",
                dict: Some("pkcs7.dict"),
                seeds: &[CTL_SEEDS],
            },
            Target {
                name: "fuzz_classify",
                dict: None,
                seeds: &[FILETYPE_SEEDS],
            },
            Target {
                name: "script_sig",
                dict: Some("script.dict"),
                seeds: &[SCRIPT_SEEDS],
            },
        ],
    },
    Project {
        dir: "crates/palisade-proto/fuzz",
        package: "palisade-proto",
        targets: &[Target {
            name: "trust_set_decode",
            dict: None,
            seeds: &[TRUST_SET_SEEDS],
        }],
    },
];

/// What to run: the time per target, and optionally a single target.
#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub seconds: u32,
    pub target: Option<String>,
}

/// Reads `[--seconds N] [--target NAME]`, in any order. Without
/// `--seconds`, each target runs for [`DEFAULT_SECONDS`].
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    const USAGE: &str = "usage: cargo xtask fuzz [--seconds N] [--target NAME]";
    let mut parsed = Args {
        seconds: DEFAULT_SECONDS,
        target: None,
    };
    let mut seen_seconds = false;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().ok_or(USAGE)?;
        match flag.as_str() {
            "--seconds" if !seen_seconds => {
                seen_seconds = true;
                parsed.seconds = match value.parse::<u32>() {
                    Ok(n) if (1..=MAX_SECONDS).contains(&n) => n,
                    _ => {
                        return Err(format!(
                            "--seconds must be a whole number from 1 to {MAX_SECONDS}, not `{value}`"
                        ));
                    }
                };
            }
            "--target" if parsed.target.is_none() => {
                let known = PROJECTS
                    .iter()
                    .flat_map(|p| p.targets)
                    .any(|t| t.name == value);
                if !known {
                    return Err(format!("unknown fuzz target `{value}`"));
                }
                parsed.target = Some(value.clone());
            }
            _ => return Err(USAGE.to_owned()),
        }
    }
    Ok(parsed)
}

/// A file libFuzzer wrote: a crash, hang, leak or out-of-memory input.
#[derive(Debug, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    /// The file's size in bytes.
    pub size: u64,
    /// Its contents, or `None` when it is larger than
    /// [`MAX_INLINE_ARTIFACT`] and was not read.
    pub bytes: Option<Vec<u8>>,
}

/// The result of one target.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub target: &'static str,
    /// The project directory, relative to the repository root.
    pub dir: &'static str,
    /// Seed inputs in the corpus before the run.
    pub seeds: usize,
    /// `None` when the target passed; otherwise why it failed.
    pub failure: Option<String>,
    pub artifacts: Vec<Artifact>,
}

/// Builds and runs every target from `root` for `seconds` each. Returns the
/// outcomes; an `Err` means a project could not be built at all.
pub fn run(root: &Path, args: &Args) -> Result<Vec<Outcome>, String> {
    let seconds = args.seconds;
    if !nightly(root, &["fuzz", "--version"])
        .status()
        .is_ok_and(|s| s.success())
    {
        return Err(format!(
            "cargo-fuzz on {TOOLCHAIN} is needed:\n  rustup toolchain install {TOOLCHAIN} --profile minimal\n  cargo install --locked {CARGO_FUZZ}"
        ));
    }
    let work = root.join("target").join("fuzz-smoke");
    let mut outcomes = Vec::new();
    for project in PROJECTS {
        let selected: Vec<&Target> = project
            .targets
            .iter()
            .filter(|t| args.target.as_deref().is_none_or(|name| t.name == name))
            .collect();
        if selected.is_empty() {
            continue;
        }
        let fuzz_dir = root.join(project.dir);
        let crate_dir = fuzz_dir
            .parent()
            .ok_or_else(|| format!("{}: no parent directory", project.dir))?
            .to_path_buf();
        // The fuzz project is its own workspace with its own committed
        // lockfile. cargo-fuzz has no `--locked`, so the nightly cargo that
        // builds it first fetches with `--locked`, which fails if the
        // lockfile is out of date. The build and runs are then offline, so
        // they can neither download anything nor re-resolve the lockfile.
        let manifest = fuzz_dir.join("Cargo.toml");
        let fetched = nightly(root, &["fetch", "--locked", "--manifest-path"])
            .arg(&manifest)
            .env_remove("CARGO_NET_OFFLINE")
            .status()
            .map_err(|e| format!("cannot run cargo fetch: {e}"))?;
        if !fetched.success() {
            return Err(format!(
                "{}/Cargo.lock is missing or out of date; update it with `cargo update --manifest-path {}/Cargo.toml`",
                project.dir, project.dir
            ));
        }
        println!("fuzz: building {}", project.dir);
        let mut build = nightly(&crate_dir, &["fuzz", "build"]);
        if let [only] = selected.as_slice() {
            build.arg(only.name);
        }
        let built = build
            .status()
            .map_err(|e| format!("cannot run cargo fuzz build: {e}"))?;
        if !built.success() {
            return Err(format!("cargo fuzz build failed in {}", project.dir));
        }
        for target in selected {
            outcomes.push(run_target(
                root, project, &crate_dir, &fuzz_dir, &work, target, seconds,
            )?);
        }
    }
    Ok(outcomes)
}

fn run_target(
    root: &Path,
    project: &Project,
    crate_dir: &Path,
    fuzz_dir: &Path,
    work: &Path,
    target: &Target,
    seconds: u32,
) -> Result<Outcome, String> {
    let corpus = work.join(target.name).join("corpus");
    let artifacts = work.join(target.name).join("artifacts");
    for dir in [&corpus, &artifacts] {
        fresh_dir(dir)?;
    }
    let mut outcome = Outcome {
        target: target.name,
        dir: project.dir,
        seeds: 0,
        failure: None,
        artifacts: Vec::new(),
    };
    for seed in target.seeds {
        println!(
            "fuzz: [{}] seeding from {}::{}",
            target.name, seed.test, seed.name
        );
        let seeded = stable_cargo(root)
            .args([
                "test",
                "--locked",
                "-p",
                project.package,
                "--test",
                seed.test,
            ])
            .args(["--", "--ignored", "--exact", seed.name])
            .env("PALISADE_FUZZ_SEED_DIR", &corpus)
            .status()
            .map_err(|e| format!("cannot run cargo test: {e}"))?;
        if !seeded.success() {
            outcome.failure = Some(format!("seeding with {} failed", seed.name));
            return Ok(outcome);
        }
    }
    outcome.seeds = files_in(&corpus)?.len();
    // libtest passes when `--exact` matches no test, so a renamed or
    // un-ignored seed writer would otherwise go unnoticed.
    if !target.seeds.is_empty() && outcome.seeds == 0 {
        outcome.failure = Some("the seed writers wrote no inputs".to_owned());
        return Ok(outcome);
    }

    println!("fuzz: [{}] running for {seconds} s", target.name);
    let mut command = nightly(crate_dir, &["fuzz", "run", target.name]);
    command
        .arg(&corpus)
        .arg("--")
        .arg(format!("-max_total_time={seconds}"))
        .arg(format!("-timeout={INPUT_TIMEOUT_SECONDS}"))
        .arg(format!("-rss_limit_mb={RSS_LIMIT_MB}"))
        .arg("-print_final_stats=1");
    // libFuzzer joins the prefix and the file name as strings.
    let mut prefix = artifacts.as_os_str().to_owned();
    prefix.push(std::path::MAIN_SEPARATOR_STR);
    let mut prefix_arg = std::ffi::OsString::from("-artifact_prefix=");
    prefix_arg.push(prefix);
    command.arg(prefix_arg);
    if let Some(dict) = target.dict {
        let mut dict_arg = std::ffi::OsString::from("-dict=");
        dict_arg.push(fuzz_dir.join(dict));
        command.arg(dict_arg);
    }
    let status = command
        .status()
        .map_err(|e| format!("cannot run cargo fuzz run: {e}"))?;
    for path in files_in(&artifacts)? {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let size = std::fs::metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
            .len();
        let small = usize::try_from(size).is_ok_and(|n| n <= MAX_INLINE_ARTIFACT);
        let bytes = if small {
            Some(std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?)
        } else {
            None
        };
        outcome.artifacts.push(Artifact { name, size, bytes });
    }
    if !status.success() {
        outcome.failure = Some(format!("cargo fuzz run exited with {status}"));
    } else if !outcome.artifacts.is_empty() {
        outcome.failure = Some("libFuzzer wrote a finding".to_owned());
    }
    Ok(outcome)
}

/// `cargo +<TOOLCHAIN> <args>` in `dir`, offline. Uses the rustup proxy from
/// `PATH`, because only it understands `+toolchain`, and drops the variables
/// the outer `cargo run` set, so they cannot select the stable toolchain.
fn nightly(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("cargo");
    command
        .arg(format!("+{TOOLCHAIN}"))
        .args(args)
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env("CARGO_NET_OFFLINE", "true");
    command
}

/// The cargo that runs xtask, on the pinned stable toolchain.
fn stable_cargo(root: &Path) -> Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.current_dir(root);
    command
}

/// Removes `dir` if it exists, and creates it empty.
fn fresh_dir(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)
            .map_err(|e| format!("cannot remove {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))
}

/// The regular files directly inside `dir`, sorted. Symbolic links are not
/// followed.
fn files_in(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", entry.path().display()))?;
        if file_type.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// The Markdown summary for the job page.
pub fn markdown(seconds: u32, outcomes: &[Outcome]) -> String {
    let mut out = format!(
        "### Fuzzing: {seconds} s per target\n\n| Target | Seed inputs | Result |\n|---|---|---|\n"
    );
    for o in outcomes {
        let result = match &o.failure {
            None => "passed".to_owned(),
            Some(reason) => format!("**failed**: {}", table_text(reason)),
        };
        out.push_str(&format!("| `{}` | {} | {result} |\n", o.target, o.seeds));
    }
    for o in outcomes {
        for a in &o.artifacts {
            let name = safe_name(&a.name);
            out.push_str(&format!(
                "\n#### `{}`: `{name}` ({} bytes)\n\n",
                o.target, a.size
            ));
            let Some(bytes) = a
                .bytes
                .as_deref()
                .filter(|b| b.len() <= MAX_INLINE_ARTIFACT)
            else {
                out.push_str(&format!(
                    "Too large to show here (over {MAX_INLINE_ARTIFACT} bytes). Run `cargo xtask fuzz --seconds {seconds}` locally to find it again.\n"
                ));
                continue;
            };
            let dir = o.dir.strip_suffix("/fuzz").unwrap_or(o.dir);
            out.push_str(&format!(
                "To reproduce, from `{dir}`:\n\n```sh\nbase64 -d > {name} <<'EOF'\n{}EOF\ncargo +{TOOLCHAIN} fuzz run {} {name} -- -timeout={INPUT_TIMEOUT_SECONDS}\n```\n",
                base64_lines(bytes),
                o.target
            ));
        }
    }
    out
}

/// One `::error` workflow command per failed target.
pub fn annotations(outcomes: &[Outcome]) -> Vec<String> {
    outcomes
        .iter()
        .filter_map(|o| {
            let reason = o.failure.as_ref()?;
            let found: Vec<String> = o.artifacts.iter().map(|a| safe_name(&a.name)).collect();
            let found = if found.is_empty() {
                String::new()
            } else {
                format!(" ({})", found.join(", "))
            };
            Some(format!(
                "::error title=Fuzz target failed::{}",
                escape_data(&format!("{}: {reason}{found}", o.target))
            ))
        })
        .collect()
}

/// A libFuzzer artefact name (`crash-<sha1>` and similar) reduced to
/// characters that are safe in Markdown and in a shell command.
fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.starts_with(['.', '-']) {
        format!("input{cleaned}")
    } else {
        cleaned
    }
}

/// Text for a Markdown table cell: one line, no column breaks.
fn table_text(s: &str) -> String {
    s.replace(['\r', '\n'], " ").replace('|', "\\|")
}

/// Escaping for the message part of a workflow command.
pub fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Standard base64 (RFC 4648, with padding), in lines of 76 characters, each
/// ending in a newline.
pub fn base64_lines(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextet = |shift: u32| ALPHABET[usize::try_from((n >> shift) & 0x3f).unwrap_or(0)];
        encoded.push(sextet(18));
        encoded.push(sextet(12));
        encoded.push(if chunk.len() > 1 { sextet(6) } else { b'=' });
        encoded.push(if chunk.len() > 2 { sextet(0) } else { b'=' });
    }
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 + 1);
    for line in encoded.chunks(76) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    #[test]
    fn targets_match_each_fuzz_manifest() {
        for project in PROJECTS {
            let dir = repo().join(project.dir);
            let manifest: toml::Table = std::fs::read_to_string(dir.join("Cargo.toml"))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(
                manifest["package"]["metadata"]["cargo-fuzz"].as_bool(),
                Some(true),
                "{}",
                project.dir
            );
            let mut bins: Vec<&str> = manifest["bin"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b["name"].as_str().unwrap())
                .collect();
            let mut listed: Vec<&str> = project.targets.iter().map(|t| t.name).collect();
            bins.sort_unstable();
            listed.sort_unstable();
            assert_eq!(
                listed, bins,
                "xtask/src/fuzz.rs PROJECTS must list every [[bin]] in {}/Cargo.toml",
                project.dir
            );
            for target in project.targets {
                if let Some(dict) = target.dict {
                    assert!(dir.join(dict).is_file(), "{}: no {dict}", target.name);
                }
                for seed in target.seeds {
                    let test = repo()
                        .join("crates")
                        .join(project.package)
                        .join("tests")
                        .join(format!("{}.rs", seed.test));
                    let source = std::fs::read_to_string(&test).unwrap();
                    assert!(
                        source.contains(&format!("fn {}()", seed.name)),
                        "{} has no {}",
                        test.display(),
                        seed.name
                    );
                }
            }
        }
    }

    /// `--target`, `fuzz.yml`'s matrix and `target/fuzz-smoke/<target>/`
    /// name a target without its project, so names must be unique.
    #[test]
    fn target_names_are_unique_across_projects() {
        let mut names: Vec<&str> = PROJECTS
            .iter()
            .flat_map(|p| p.targets)
            .map(|t| t.name)
            .collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "fuzz target names must be unique");
    }

    #[test]
    fn every_fuzz_project_is_listed_and_locked() {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(repo().join("crates")).unwrap() {
            let fuzz = entry.unwrap().path().join("fuzz");
            if fuzz.join("Cargo.toml").is_file() {
                let name = fuzz.parent().unwrap().file_name().unwrap();
                found.push(format!("crates/{}/fuzz", name.to_string_lossy()));
            }
        }
        found.sort();
        let mut listed: Vec<String> = PROJECTS.iter().map(|p| p.dir.to_owned()).collect();
        listed.sort();
        assert_eq!(listed, found, "xtask/src/fuzz.rs PROJECTS is out of date");
        for project in PROJECTS {
            let dir = repo().join(project.dir);
            assert!(
                dir.join("Cargo.lock").is_file(),
                "{}/Cargo.lock must be committed, so CI builds the fuzz targets from it",
                project.dir
            );
            let ignored = std::fs::read_to_string(dir.join(".gitignore")).unwrap_or_default();
            assert!(
                !ignored.lines().any(|l| l.trim() == "Cargo.lock"),
                "{}/.gitignore must not ignore Cargo.lock",
                project.dir
            );
        }
    }

    /// Every fuzz workspace is updated by Dependabot and checked by
    /// cargo-deny on PRs and daily. cargo-audit covers it through
    /// `cargo xtask audit`, which reads [`PROJECTS`].
    #[test]
    fn every_fuzz_project_is_in_dependabot_and_cargo_deny() {
        let dependabot = std::fs::read_to_string(repo().join(".github/dependabot.yml")).unwrap();
        let docs = yaml_rust2::YamlLoader::load_from_str(&dependabot).unwrap();
        let cargo_dirs: Vec<&str> = docs[0]["updates"]
            .as_vec()
            .unwrap()
            .iter()
            .filter(|u| u["package-ecosystem"].as_str() == Some("cargo"))
            .filter_map(|u| u["directory"].as_str())
            .collect();
        let ci = std::fs::read_to_string(repo().join(".github/workflows/ci.yml")).unwrap();
        let audit = std::fs::read_to_string(repo().join(".github/workflows/audit.yml")).unwrap();
        let joined = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let (ci, audit) = (joined(&ci), joined(&audit));
        for project in PROJECTS {
            let dir = format!("/{}", project.dir);
            assert!(
                cargo_dirs.contains(&dir.as_str()),
                ".github/dependabot.yml needs a cargo entry for {dir}"
            );
            let deny = format!(
                "cargo deny --locked --manifest-path {}/Cargo.toml --config deny.toml check",
                project.dir
            );
            assert!(ci.contains(&deny), "ci.yml must run `{deny}`");
            assert!(
                audit.contains(&format!("{deny} advisories")),
                "audit.yml must run `{deny} advisories`"
            );
        }
    }

    #[test]
    fn workflows_install_the_pinned_toolchain_and_cargo_fuzz() {
        for workflow in ["ci.yml", "fuzz.yml"] {
            let source =
                std::fs::read_to_string(repo().join(".github/workflows").join(workflow)).unwrap();
            assert!(
                source.contains(&format!(
                    "rustup toolchain install {TOOLCHAIN} --profile minimal"
                )),
                "{workflow} must install {TOOLCHAIN}"
            );
            assert!(
                source.contains(&format!("tool: {CARGO_FUZZ}")),
                "{workflow} must install {CARGO_FUZZ}"
            );
        }
    }

    #[test]
    fn scheduled_workflow_runs_every_target() {
        let source = std::fs::read_to_string(repo().join(".github/workflows/fuzz.yml")).unwrap();
        let docs = yaml_rust2::YamlLoader::load_from_str(&source).unwrap();
        let mut matrix: Vec<&str> = docs[0]["jobs"]["fuzz"]["strategy"]["matrix"]["target"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        let mut all: Vec<&str> = PROJECTS
            .iter()
            .flat_map(|p| p.targets)
            .map(|t| t.name)
            .collect();
        matrix.sort_unstable();
        all.sort_unstable();
        assert_eq!(matrix, all, "fuzz.yml must run every target in PROJECTS");
    }

    #[test]
    fn arguments_are_parsed_and_bounded() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let parsed = |seconds, target: Option<&str>| {
            Ok(Args {
                seconds,
                target: target.map(str::to_owned),
            })
        };
        assert_eq!(parse_args(&[]), parsed(DEFAULT_SECONDS, None));
        assert_eq!(
            parse_args(&args(&["--seconds", "1800"])),
            parsed(1800, None)
        );
        assert_eq!(
            parse_args(&args(&["--seconds", "3600"])),
            parsed(3600, None)
        );
        assert_eq!(
            parse_args(&args(&["--target", "pe_parse", "--seconds", "5"])),
            parsed(5, Some("pe_parse"))
        );
        for bad in ["0", "3601", "-1", "1.5", "", "60s"] {
            assert!(parse_args(&args(&["--seconds", bad])).is_err(), "{bad}");
        }
        for bad in [
            &["--secs", "5"][..],
            &["--seconds"],
            &["--seconds", "5", "--seconds", "6"],
            &["--target", "no_such_target"],
            &["--target", "pe_parse", "--target", "fsctx_parse"],
            &["pe_parse"],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg==\n"),
            (b"fo", "Zm8=\n"),
            (b"foo", "Zm9v\n"),
            (b"foob", "Zm9vYg==\n"),
            (b"fooba", "Zm9vYmE=\n"),
            (b"foobar", "Zm9vYmFy\n"),
        ];
        for (input, expected) in cases {
            assert_eq!(base64_lines(input), expected);
        }
        let all: Vec<u8> = (0..=255).collect();
        let encoded = base64_lines(&all);
        assert!(encoded.lines().all(|l| l.len() <= 76));
        assert!(encoded.starts_with(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4
"
        ));
        assert!(encoded.ends_with("/P3+/w==\n"));
        assert_eq!(encoded.replace('\n', "").len(), 344);
    }

    fn outcome(failure: Option<&str>, artifacts: Vec<Artifact>) -> Outcome {
        Outcome {
            target: "pe_parse",
            dir: "crates/palisade-fileid/fuzz",
            seeds: 6,
            failure: failure.map(str::to_owned),
            artifacts,
        }
    }

    #[test]
    fn passing_run_is_summarised() {
        let md = markdown(60, &[outcome(None, Vec::new())]);
        assert_eq!(
            md,
            "### Fuzzing: 60 s per target\n\n| Target | Seed inputs | Result |\n|---|---|---|\n| `pe_parse` | 6 | passed |\n"
        );
        assert!(annotations(&[outcome(None, Vec::new())]).is_empty());
    }

    #[test]
    fn crash_is_shown_with_a_reproducer() {
        let crash = Artifact {
            name: "crash-0a1b".to_owned(),
            size: 3,
            bytes: Some(b"MZ\x00".to_vec()),
        };
        let o = outcome(Some("cargo fuzz run exited with 1"), vec![crash]);
        let md = markdown(60, std::slice::from_ref(&o));
        assert!(
            md.contains("| `pe_parse` | 6 | **failed**: cargo fuzz run exited with 1 |"),
            "{md}"
        );
        assert!(
            md.contains("#### `pe_parse`: `crash-0a1b` (3 bytes)"),
            "{md}"
        );
        assert!(md.contains("from `crates/palisade-fileid`"), "{md}");
        assert!(
            md.contains("base64 -d > crash-0a1b <<'EOF'\nTVoA\nEOF\n"),
            "{md}"
        );
        assert!(
            md.contains(&format!(
                "cargo +{TOOLCHAIN} fuzz run pe_parse crash-0a1b -- -timeout={INPUT_TIMEOUT_SECONDS}\n"
            )),
            "{md}"
        );
        assert_eq!(
            annotations(&[o]),
            [
                "::error title=Fuzz target failed::pe_parse: cargo fuzz run exited with 1 (crash-0a1b)"
            ]
        );
    }

    #[test]
    fn large_artifacts_are_not_inlined() {
        let big = Artifact {
            name: "oom-1".to_owned(),
            size: 1 << 30,
            bytes: None,
        };
        let md = markdown(60, &[outcome(Some("x"), vec![big])]);
        assert!(md.contains("Too large to show here"), "{md}");
        assert!(md.contains("(1073741824 bytes)"), "{md}");
        assert!(!md.contains("base64 -d"), "{md}");
    }

    #[test]
    fn untrusted_names_and_reasons_cannot_break_out() {
        assert_eq!(safe_name("crash-$(rm -rf ~)`x`"), "crash-__rm_-rf____x_");
        assert_eq!(safe_name("-rf"), "input-rf");
        assert_eq!(safe_name(""), "input");
        let o = outcome(Some("a|b\n::add-mask::c 5%"), Vec::new());
        assert!(
            markdown(1, std::slice::from_ref(&o)).contains("**failed**: a\\|b ::add-mask::c 5% |")
        );
        assert_eq!(
            annotations(&[o]),
            ["::error title=Fuzz target failed::pe_parse: a|b%0A::add-mask::c 5%25"]
        );
    }
}
