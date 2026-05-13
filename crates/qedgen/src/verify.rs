// The `verify` subcommand runs the generated harnesses against the generated
// implementation. It closes the loop that `check` opens: check validates the
// spec; verify validates the code the spec produced.
//
// Backends: proptest (cargo test), kani (cargo kani — M2), lean (lake build).
// Each runner returns a BackendReport; they roll up into a VerifyReport.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::verify_counterexample::Counterexample;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Serialize)]
pub struct BackendReport {
    pub name: &'static str,
    pub status: BackendStatus,
    pub duration_ms: u128,
    pub detail: Option<String>,
    pub log_path: Option<PathBuf>,
    /// Structured counterexamples extracted by the per-backend parser
    /// (PLAN-v2.16 D1/D2). Empty for `Passed` / `Skipped` backends, and
    /// for `Failed` backends whose parser couldn't extract structured
    /// data (in which case `detail` still carries the human summary).
    /// Serialized `omitempty` so consumers pinning the v2.15 shape
    /// continue to work.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub counterexamples: Vec<Counterexample>,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub spec: PathBuf,
    pub backends: Vec<BackendReport>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.backends
            .iter()
            .all(|b| !matches!(b.status, BackendStatus::Failed))
    }
}

pub struct VerifyOpts {
    pub spec: PathBuf,
    pub proptest: bool,
    pub proptest_path: PathBuf,
    pub kani: bool,
    pub kani_path: PathBuf,
    pub lean: bool,
    pub lean_dir: PathBuf,
    pub fail_fast: bool,
}

pub fn run(opts: &VerifyOpts) -> Result<VerifyReport> {
    let mut backends = Vec::new();

    if opts.proptest {
        let report = run_proptest(&opts.proptest_path);
        let failed = matches!(report.status, BackendStatus::Failed);
        backends.push(report);
        if failed && opts.fail_fast {
            return Ok(VerifyReport {
                spec: opts.spec.clone(),
                backends,
            });
        }
    }

    if opts.kani {
        let report = run_kani(&opts.kani_path);
        let failed = matches!(report.status, BackendStatus::Failed);
        backends.push(report);
        if failed && opts.fail_fast {
            return Ok(VerifyReport {
                spec: opts.spec.clone(),
                backends,
            });
        }
    }

    if opts.lean {
        let report = run_lean(&opts.lean_dir);
        let failed = matches!(report.status, BackendStatus::Failed);
        backends.push(report);
        if failed && opts.fail_fast {
            return Ok(VerifyReport {
                spec: opts.spec.clone(),
                backends,
            });
        }
    }

    Ok(VerifyReport {
        spec: opts.spec.clone(),
        backends,
    })
}

fn run_proptest(harness: &Path) -> BackendReport {
    let start = Instant::now();

    if !harness.exists() {
        return BackendReport {
            name: "proptest",
            status: BackendStatus::Skipped,
            duration_ms: start.elapsed().as_millis(),
            detail: Some(format!(
                "harness not found at {} (run `qedgen codegen --proptest`)",
                harness.display()
            )),
            log_path: None,
            counterexamples: Vec::new(),
        };
    }

    // The harness is generated into `tests/proptest.rs` at the program root;
    // its containing crate is whatever cargo finds walking up. Run from the
    // harness's nearest Cargo.toml ancestor.
    let crate_dir = match nearest_cargo_dir(harness) {
        Some(dir) => dir,
        None => {
            return BackendReport {
                name: "proptest",
                status: BackendStatus::Failed,
                duration_ms: start.elapsed().as_millis(),
                detail: Some(format!("no Cargo.toml found above {}", harness.display())),
                log_path: None,
                counterexamples: Vec::new(),
            };
        }
    };

    // `cargo test --release --test proptest` runs just the generated harness.
    // Release because proptest cases can be slow under debug.
    let test_name = harness
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("proptest");

    let output = Command::new("cargo")
        .args(["test", "--release", "--test", test_name])
        .current_dir(&crate_dir)
        .output();

    let duration_ms = start.elapsed().as_millis();

    match output {
        Ok(out) if out.status.success() => BackendReport {
            name: "proptest",
            status: BackendStatus::Passed,
            duration_ms,
            detail: None,
            log_path: None,
            counterexamples: Vec::new(),
        },
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            // PLAN-v2.16 D2: parse libtest's failure block into structured
            // (harness, var, value) tuples. Then attach the persisted
            // proptest-regressions seed for deterministic re-run. If
            // parsing yields nothing (output shape changed, or failure
            // happened before any property fired), `detail` still carries
            // the existing human summary so nothing regresses.
            let mut cxs = crate::verify_proptest_parse::parse_failures(&stdout);
            for cx in cxs.iter_mut() {
                cx.seed =
                    crate::verify_proptest_parse::read_seed_for_harness(&crate_dir, test_name);
            }
            BackendReport {
                name: "proptest",
                status: BackendStatus::Failed,
                duration_ms,
                detail: Some(summarize_cargo_failure(&stdout, &stderr)),
                log_path: None,
                counterexamples: cxs,
            }
        }
        Err(e) => BackendReport {
            name: "proptest",
            status: BackendStatus::Failed,
            duration_ms,
            detail: Some(format!("failed to spawn cargo: {}", e)),
            log_path: None,
            counterexamples: Vec::new(),
        },
    }
}

fn run_kani(harness: &Path) -> BackendReport {
    let start = Instant::now();

    if !harness.exists() {
        return BackendReport {
            name: "kani",
            status: BackendStatus::Skipped,
            duration_ms: start.elapsed().as_millis(),
            detail: Some(format!(
                "harness not found at {} (run `qedgen codegen --kani`)",
                harness.display()
            )),
            log_path: None,
            counterexamples: Vec::new(),
        };
    }

    // Point-of-use dep check. `require_kani` returns Err with install text
    // when cargo-kani is missing; surface that as a Failed backend so the
    // user sees the install hint instead of a spawn error.
    if let Err(e) = crate::deps::require_kani() {
        return BackendReport {
            name: "kani",
            status: BackendStatus::Failed,
            duration_ms: start.elapsed().as_millis(),
            detail: Some(format!("{}", e)),
            log_path: None,
            counterexamples: Vec::new(),
        };
    }

    // If the harness routes any effect to `bin = "z3"` (wide-type mul/div),
    // preflight that z3 is installed. Without this the Kani run fails with
    // an opaque cbmc spawn error; surface the install hint up front.
    if let Err(e) = crate::deps::require_z3_if_kani_harness_needs_it(harness) {
        return BackendReport {
            name: "kani",
            status: BackendStatus::Failed,
            duration_ms: start.elapsed().as_millis(),
            detail: Some(format!("{}", e)),
            log_path: None,
            counterexamples: Vec::new(),
        };
    }

    let crate_dir = match nearest_cargo_dir(harness) {
        Some(dir) => dir,
        None => {
            return BackendReport {
                name: "kani",
                status: BackendStatus::Failed,
                duration_ms: start.elapsed().as_millis(),
                detail: Some(format!("no Cargo.toml found above {}", harness.display())),
                log_path: None,
                counterexamples: Vec::new(),
            };
        }
    };

    // `--tests` scopes Kani to #[kani::proof] functions under tests/.
    // The generated harness is `#![cfg(kani)]`, so `cargo test` ignores
    // it and only `cargo kani` picks it up.
    let output = Command::new("cargo")
        .args(["kani", "--tests"])
        .current_dir(&crate_dir)
        .output();

    let duration_ms = start.elapsed().as_millis();

    match output {
        Ok(out) if out.status.success() => BackendReport {
            name: "kani",
            status: BackendStatus::Passed,
            duration_ms,
            detail: Some(summarize_kani_pass(&String::from_utf8_lossy(&out.stdout))),
            log_path: None,
            counterexamples: Vec::new(),
        },
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            // PLAN-v2.16 D1: parse CBMC counterexample output into
            // structured (harness, var, value, line) tuples. The human
            // `detail` summary stays for backward compat / pretty-print.
            // Counterexamples come exclusively from stdout (cargo-kani
            // routes verdicts there); stderr carries build noise we
            // fold into `detail` only.
            let cxs = crate::verify_kani_parse::parse_failures(&stdout);
            BackendReport {
                name: "kani",
                status: BackendStatus::Failed,
                duration_ms,
                detail: Some(summarize_kani_failure(&stdout, &stderr)),
                log_path: None,
                counterexamples: cxs,
            }
        }
        Err(e) => BackendReport {
            name: "kani",
            status: BackendStatus::Failed,
            duration_ms,
            detail: Some(format!("failed to spawn cargo kani: {}", e)),
            log_path: None,
            counterexamples: Vec::new(),
        },
    }
}

fn run_lean(lean_dir: &Path) -> BackendReport {
    let start = Instant::now();

    if !lean_dir.join("lakefile.lean").exists() && !lean_dir.join("lakefile.toml").exists() {
        return BackendReport {
            name: "lean",
            status: BackendStatus::Skipped,
            duration_ms: start.elapsed().as_millis(),
            detail: Some(format!(
                "no lakefile in {} (run `qedgen codegen --lean`)",
                lean_dir.display()
            )),
            log_path: None,
            counterexamples: Vec::new(),
        };
    }

    let output = Command::new("lake")
        .arg("build")
        .current_dir(lean_dir)
        .output();

    let duration_ms = start.elapsed().as_millis();

    match output {
        Ok(out) if out.status.success() => BackendReport {
            name: "lean",
            status: BackendStatus::Passed,
            duration_ms,
            detail: None,
            log_path: None,
            counterexamples: Vec::new(),
        },
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            BackendReport {
                name: "lean",
                status: BackendStatus::Failed,
                duration_ms,
                detail: Some(summarize_lake_failure(&stdout, &stderr)),
                log_path: None,
                counterexamples: Vec::new(),
            }
        }
        Err(e) => BackendReport {
            name: "lean",
            status: BackendStatus::Failed,
            duration_ms,
            detail: Some(format!(
                "failed to spawn lake: {} (is lean/lake on PATH?)",
                e
            )),
            log_path: None,
            counterexamples: Vec::new(),
        },
    }
}

fn nearest_cargo_dir(start: &Path) -> Option<PathBuf> {
    let mut cur = if start.is_dir() {
        Some(start.to_path_buf())
    } else {
        start.parent().map(|p| p.to_path_buf())
    };
    while let Some(dir) = cur {
        if dir.join("Cargo.toml").exists() {
            return Some(dir);
        }
        cur = dir.parent().map(|p| p.to_path_buf());
    }
    None
}

fn summarize_cargo_failure(stdout: &str, stderr: &str) -> String {
    // Prefer the test-failure lines if present; fall back to the tail of stderr.
    let failures: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("FAILED") || l.contains("test result: FAILED"))
        .take(10)
        .collect();
    if !failures.is_empty() {
        return failures.join("\n");
    }
    tail_lines(stderr, 20)
}

fn summarize_kani_pass(stdout: &str) -> String {
    // On success, Kani prints "VERIFICATION:- SUCCESSFUL" per harness and a
    // summary line. Count them for a tight report.
    let successful = stdout.matches("VERIFICATION:- SUCCESSFUL").count();
    let summary_line = stdout
        .lines()
        .find(|l| l.contains("Complete - ") || l.contains("harnesses"))
        .unwrap_or("");
    if summary_line.is_empty() {
        format!("{} harness(es) verified", successful)
    } else {
        format!("{} verified — {}", successful, summary_line.trim())
    }
}

fn summarize_kani_failure(stdout: &str, stderr: &str) -> String {
    // Pull failed verifications and their counterexample preamble.
    let mut lines: Vec<&str> = stdout
        .lines()
        .filter(|l| {
            l.contains("VERIFICATION:- FAILED")
                || l.contains("Failed Checks:")
                || l.contains("Failed properties:")
                || l.contains("Check ")
        })
        .take(20)
        .collect();
    if lines.is_empty() {
        // Failure before any harness ran (toolchain missing, cargo metadata
        // refused, etc). `cargo kani` writes some of these to stdout and some
        // to stderr; return whichever has content.
        let tail_err = tail_lines(stderr, 20);
        if !tail_err.trim().is_empty() {
            return tail_err;
        }
        let tail_out = tail_lines(stdout, 20);
        if !tail_out.trim().is_empty() {
            return tail_out;
        }
        return "cargo kani failed with no diagnostic output".into();
    }
    if let Some(summary) = stdout
        .lines()
        .find(|l| l.contains("Complete - ") || l.contains("Summary:"))
    {
        lines.push(summary);
    }
    lines.join("\n")
}

fn summarize_lake_failure(stdout: &str, stderr: &str) -> String {
    let errors: Vec<&str> = stderr
        .lines()
        .chain(stdout.lines())
        .filter(|l| l.contains("error:") || l.contains("sorry"))
        .take(10)
        .collect();
    if !errors.is_empty() {
        return errors.join("\n");
    }
    tail_lines(stderr, 20)
}

fn tail_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

pub fn print_human(report: &VerifyReport) {
    eprint!("{}", format_human(report));
}

/// Format the full human-readable verify report. Separated from `print_human`
/// so tests can pin the exact rendering without stderr capture; `print_human`
/// is the side-effecting thin wrapper. Returns a string ending in a newline.
pub fn format_human(report: &VerifyReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("qedgen verify — {}\n", report.spec.display()));
    for b in &report.backends {
        let marker = match b.status {
            BackendStatus::Passed => "PASS",
            BackendStatus::Failed => "FAIL",
            BackendStatus::Skipped => "SKIP",
        };
        out.push_str(&format!(
            "  [{}] {:<10} ({} ms)\n",
            marker, b.name, b.duration_ms
        ));
        if let Some(d) = &b.detail {
            for line in d.lines() {
                out.push_str(&format!("         {}\n", line));
            }
        }
        format_counterexamples(&mut out, &b.counterexamples);
    }
    if report.ok() {
        out.push_str("OK\n");
    } else {
        out.push_str("FAILED\n");
    }
    out
}

/// Render each backend's structured counterexamples below its status line,
/// one block per failing harness with the spec-named `var = value` pairs the
/// per-backend parser extracted. Both the kani parser (CBMC state blocks)
/// and the proptest parser already preserve spec binder names from the
/// generated harness — this fn is just the human surface for that data.
/// JSON consumers see the same data via `BackendReport.counterexamples`.
fn format_counterexamples(out: &mut String, cxs: &[Counterexample]) {
    for cx in cxs {
        out.push_str(&format!("         counterexample: {}\n", cx.harness));
        if let Some(msg) = &cx.failure_message {
            out.push_str(&format!("           {}\n", msg));
        }
        if let Some(loc) = &cx.source_location {
            out.push_str(&format!("           at {}\n", loc));
        }
        if !cx.assignments.is_empty() {
            let name_width = cx
                .assignments
                .iter()
                .map(|a| a.name.len())
                .max()
                .unwrap_or(0);
            for a in &cx.assignments {
                out.push_str(&format!(
                    "             {:<width$} = {}\n",
                    a.name,
                    a.value,
                    width = name_width
                ));
            }
        }
        if let Some(seed) = &cx.seed {
            out.push_str(&format!("           seed: {}\n", seed));
        }
    }
}

pub fn print_json(report: &VerifyReport) -> Result<()> {
    let s = serde_json::to_string_pretty(report).context("serializing verify report")?;
    println!("{}", s);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_counterexample::{Counterexample, CounterexampleVar};

    fn cx_kani_overflow() -> Counterexample {
        Counterexample {
            harness: "probe_overflow_transfer".into(),
            status: "failed".into(),
            assignments: vec![
                CounterexampleVar {
                    name: "pre".into(),
                    value: "18446744073709551615ul".into(),
                    line: Some(38),
                },
                CounterexampleVar {
                    name: "amount".into(),
                    value: "1ul".into(),
                    line: Some(39),
                },
                CounterexampleVar {
                    name: "post".into(),
                    value: "0ul".into(),
                    line: Some(40),
                },
            ],
            seed: None,
            failure_message: Some(
                "assertion failed: post == pre.checked_add(amount).unwrap_or(0)".into(),
            ),
            source_location: Some("tests/kani.rs:42:5".into()),
        }
    }

    fn cx_proptest_lifecycle() -> Counterexample {
        Counterexample {
            harness: "deposit_preserves_lifecycle".into(),
            status: "failed".into(),
            assignments: vec![
                CounterexampleVar {
                    name: "deposit_amount".into(),
                    value: "0".into(),
                    line: None,
                },
                CounterexampleVar {
                    name: "receive_amount".into(),
                    value: "42".into(),
                    line: None,
                },
            ],
            seed: Some("proptest-regressions/lib.txt::cc 0123".into()),
            failure_message: Some("deposit must reject zero amount".into()),
            source_location: None,
        }
    }

    #[test]
    fn renders_kani_counterexample_with_named_assignments() {
        let report = VerifyReport {
            spec: PathBuf::from("program.qedspec"),
            backends: vec![BackendReport {
                name: "kani",
                status: BackendStatus::Failed,
                duration_ms: 1234,
                detail: Some("1 of 2 failed".into()),
                log_path: None,
                counterexamples: vec![cx_kani_overflow()],
            }],
        };
        let out = format_human(&report);
        // Named-value assignments render in human output, not just JSON
        // (this is the v2.17 fix — the kani parser already extracted them,
        // print_human just wasn't rendering them).
        assert!(out.contains("counterexample: probe_overflow_transfer"));
        assert!(out.contains("at tests/kani.rs:42:5"));
        assert!(out.contains("pre    = 18446744073709551615ul"));
        assert!(out.contains("amount = 1ul"));
        assert!(out.contains("post   = 0ul"));
        // Width-aligned columns: shorter name gets right-padding to longest.
        // Filter for assignment rows specifically (13-space indent + name) so
        // we don't match the failure-message line that contains `post == ...`.
        let pre_line = out
            .lines()
            .find(|l| l.starts_with("             pre"))
            .unwrap();
        let post_line = out
            .lines()
            .find(|l| l.starts_with("             post"))
            .unwrap();
        let pre_eq = pre_line.find('=').unwrap();
        let post_eq = post_line.find('=').unwrap();
        assert_eq!(pre_eq, post_eq, "name column should be width-aligned");
    }

    #[test]
    fn renders_proptest_counterexample_with_seed() {
        let report = VerifyReport {
            spec: PathBuf::from("program.qedspec"),
            backends: vec![BackendReport {
                name: "proptest",
                status: BackendStatus::Failed,
                duration_ms: 50,
                detail: None,
                log_path: None,
                counterexamples: vec![cx_proptest_lifecycle()],
            }],
        };
        let out = format_human(&report);
        assert!(out.contains("counterexample: deposit_preserves_lifecycle"));
        assert!(out.contains("deposit must reject zero amount"));
        assert!(out.contains("deposit_amount = 0"));
        assert!(out.contains("receive_amount = 42"));
        assert!(out.contains("seed: proptest-regressions/lib.txt::cc 0123"));
    }

    #[test]
    fn renders_multiple_backends_with_mixed_status() {
        let report = VerifyReport {
            spec: PathBuf::from("program.qedspec"),
            backends: vec![
                BackendReport {
                    name: "proptest",
                    status: BackendStatus::Passed,
                    duration_ms: 12,
                    detail: None,
                    log_path: None,
                    counterexamples: vec![],
                },
                BackendReport {
                    name: "kani",
                    status: BackendStatus::Failed,
                    duration_ms: 4567,
                    detail: Some("1 of 1 failed".into()),
                    log_path: None,
                    counterexamples: vec![cx_kani_overflow()],
                },
                BackendReport {
                    name: "lean",
                    status: BackendStatus::Skipped,
                    duration_ms: 0,
                    detail: Some("no lakefile".into()),
                    log_path: None,
                    counterexamples: vec![],
                },
            ],
        };
        let out = format_human(&report);
        assert!(out.contains("[PASS] proptest"));
        assert!(out.contains("[FAIL] kani"));
        assert!(out.contains("[SKIP] lean"));
        // Only the failed backend renders its counterexample block.
        assert!(out.contains("counterexample: probe_overflow_transfer"));
        // Counterexamples are nested under their backend's block, not at
        // top level — verify the order: kani line, then its counterexample.
        let kani_idx = out.find("[FAIL] kani").unwrap();
        let cx_idx = out.find("counterexample:").unwrap();
        assert!(cx_idx > kani_idx);
        assert!(out.ends_with("FAILED\n"));
    }

    #[test]
    fn passing_report_omits_counterexamples_and_ends_ok() {
        let report = VerifyReport {
            spec: PathBuf::from("program.qedspec"),
            backends: vec![BackendReport {
                name: "kani",
                status: BackendStatus::Passed,
                duration_ms: 100,
                detail: None,
                log_path: None,
                counterexamples: vec![],
            }],
        };
        let out = format_human(&report);
        assert!(!out.contains("counterexample"));
        assert!(out.ends_with("OK\n"));
    }
}
