//! Crucible fuzz harness codegen — v2.18.
//!
//! Produces a `fuzz/<program>/` directory containing a Crucible
//! (https://github.com/asymmetric-research/crucible) fuzz harness derived
//! mechanically from a `.qedspec`. Same backend-codegen pattern as
//! `kani.rs` and `proptest_gen.rs`: `pub fn generate(spec, output_dir)`
//! is the entry point.
//!
//! ## What gets emitted
//!
//! ```text
//! fuzz/<program>/
//! ├── Cargo.toml             # workspace=[], Crucible deps pinned, [features] invariant_test
//! ├── rust-toolchain.toml    # channel = "stable"
//! ├── .gitignore             # target/, crashes/, .fuzz-cache/
//! ├── idls/
//! │   └── README.md          # "drop your IDL here as <name>.json"
//! └── src/
//!     └── main.rs            # the harness — fixture + actions + invariants
//! ```
//!
//! ## Spec → harness mapping
//!
//! - `state { ... }` (mutable fields)         → `Fixture` struct fields (shadowed from LiteSVM after each action)
//! - `program_id "..."`                       → `ctx.add_program(...)` in `setup()`
//! - `handler X { ... }`                      → `pub fn action_x(&mut self, ...) -> bool { ... }`
//! - handler args + bounds                    → `#[range(lo..hi)]` annotations
//! - `invariant Foo : <expr>` (rust_expr)     → `fn invariant_foo(fixture: &mut F)` with `fuzz_assert!`
//! - `property X { ... preserved_by ... }`    → same as invariant (one `invariant_x` fn)
//!
//! ## Scope cap (Anchor only in v2.18)
//!
//! v2.18 ships Anchor-target emission only. sBPF / Pinocchio / Quasar are
//! deferred. `generate()` errors early for sBPF specs.

use anyhow::{bail, Result};
use std::path::Path;

use crate::check::{self, ParsedHandler, ParsedInvariant, ParsedProperty, ParsedSpec};
use crate::rust_codegen_util;

/// Top-level entry point. Writes a `fuzz/<program>/` directory at
/// `output_dir`. `output_dir` is expected to be the *parent* directory
/// containing the harness — e.g. `fuzz/` — and the function appends the
/// spec name as the subdirectory. Caller may also pass the leaf directly
/// (the function tolerates both — see logic in `harness_dir_for`).
pub fn generate(spec: &ParsedSpec, output_dir: &Path) -> Result<()> {
    if spec.handlers.is_empty() {
        bail!("No handlers found in spec — nothing to fuzz");
    }
    if is_sbpf_target(spec) {
        bail!(
            "Crucible codegen targets Anchor programs only in v2.18. \
             sBPF/Pinocchio support is a planned follow-up."
        );
    }

    let dir = harness_dir_for(spec, output_dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::create_dir_all(dir.join("idls"))?;

    std::fs::write(dir.join("Cargo.toml"), emit_cargo_toml(spec))?;
    std::fs::write(dir.join("rust-toolchain.toml"), RUST_TOOLCHAIN)?;
    std::fs::write(dir.join(".gitignore"), GITIGNORE)?;
    std::fs::write(dir.join("idls").join("README.md"), emit_idls_readme(spec))?;
    std::fs::write(dir.join("src").join("main.rs"), emit_harness(spec)?)?;

    eprintln!(
        "Generated Crucible fuzz harness at {} ({} action(s), {} invariant(s))",
        dir.display(),
        spec.handlers.len(),
        linked_invariant_count(spec),
    );

    Ok(())
}

/// Pick the harness leaf directory. If `output_dir` already ends with the
/// spec's snake-case name, treat it as the leaf; otherwise append it. Lets
/// callers pass either `./fuzz/` (parent) or `./fuzz/my_program/` (leaf).
fn harness_dir_for(spec: &ParsedSpec, output_dir: &Path) -> std::path::PathBuf {
    let leaf = spec_program_name(spec);
    if output_dir.file_name().and_then(|s| s.to_str()) == Some(leaf.as_str()) {
        output_dir.to_path_buf()
    } else {
        output_dir.join(leaf)
    }
}

/// Snake-case program name derived from the spec. Mirrors the convention
/// used by codegen.rs for the program crate name.
fn spec_program_name(spec: &ParsedSpec) -> String {
    let raw: &str = if spec.program_name.is_empty() {
        "program"
    } else {
        spec.program_name.as_str()
    };
    let mut out = String::new();
    let mut prev_lower = false;
    for c in raw.chars() {
        if c.is_uppercase() {
            if prev_lower {
                out.push('_');
            }
            for lc in c.to_lowercase() {
                out.push(lc);
            }
            prev_lower = false;
        } else if c == '-' || c == ' ' {
            out.push('_');
            prev_lower = false;
        } else {
            out.push(c);
            prev_lower = c.is_lowercase() || c.is_ascii_digit();
        }
    }
    out
}

fn is_sbpf_target(spec: &ParsedSpec) -> bool {
    spec.is_assembly_target()
}

fn linked_invariant_count(spec: &ParsedSpec) -> usize {
    spec.invariants
        .iter()
        .filter(|i| {
            i.rust_expr
                .as_ref()
                .map(|r| !check::rust_expr_is_unsupported(r))
                .unwrap_or(false)
        })
        .filter(|i| {
            spec.handlers
                .iter()
                .any(|h| h.invariants.contains(&i.name) || h.establishes.contains(&i.name))
        })
        .count()
}

// ============================================================================
// Static file content
// ============================================================================

const RUST_TOOLCHAIN: &str = r#"[toolchain]
channel = "stable"
"#;

const GITIGNORE: &str = r#"target/
crashes/
corpus/
.fuzz-cache/
*.lcov
"#;

fn emit_idls_readme(spec: &ParsedSpec) -> String {
    let prog = spec_program_name(spec);
    format!(
        r#"# IDLs for Crucible fuzz harness

Drop the Anchor IDL JSON for `{prog}` here as `{prog}.json`. The simplest
path:

```
# from the program crate root:
anchor build
cp target/idl/{prog}.json ../path/to/fuzz/{prog}/idls/{prog}.json
```

`qedgen probe --fuzz` will look up `target/idl/{prog}.json` and symlink it
into this directory automatically if it exists. Manual copy is the
fallback when discovery doesn't apply (Codama / non-Anchor / hand-rolled).

The IDL must be in Anchor 0.30+ format. Anchor 0.29 IDLs need
`anchor idl convert` first.
"#
    )
}

// ============================================================================
// Cargo.toml
// ============================================================================

/// The Crucible deps are pinned by git ref (Crucible v0.x — no stable
/// crates.io release yet). Worth checking the resolved git ref into the
/// emitted `Cargo.lock` so the harness reproduces.
const CRUCIBLE_DEP: &str = r#"crucible-fuzzer = { git = "https://github.com/asymmetric-research/crucible", branch = "main" }
crucible-test-context = { git = "https://github.com/asymmetric-research/crucible", branch = "main" }
crucible-idl-gen = { git = "https://github.com/asymmetric-research/crucible", branch = "main" }"#;

fn emit_cargo_toml(spec: &ParsedSpec) -> String {
    let prog = spec_program_name(spec);
    format!(
        r#"# ---- GENERATED BY QEDGEN ----
# Crucible fuzz harness for `{prog}`.
#
# Workspace is empty on purpose — isolates the harness's Solana/Anchor
# version chain (Solana v3 + Anchor 1.0.1) from the parent program crate
# (which may pin earlier versions). See Crucible docs.
# ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ----

[package]
name = "{prog}_fuzz"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
{CRUCIBLE_DEP}
anchor-lang = "1.0.1"
solana-pubkey = "3.0"
solana-keypair = "3.1"
solana-signer = "3.0"
solana-program = "3.0"
solana-message = "3.0"
solana-signature = "3.1"
solana-instruction = "3.1"
libafl = {{ version = "0.15.1", features = ["std", "cli", "prelude"] }}
libafl_bolts = {{ version = "0.15.1", features = ["std"] }}
arbitrary = {{ version = "1", features = ["derive"] }}
anyhow = "1.0"
bytemuck = "1.14"
ctor = "0.6"
ctrlc = "3.4"

[[bin]]
name = "invariant_test"
path = "src/main.rs"

[features]
invariant_test = []
"#
    )
}

// ============================================================================
// Harness body
// ============================================================================

fn emit_harness(spec: &ParsedSpec) -> Result<String> {
    let prog = spec_program_name(spec);
    let fixture = fixture_name(spec);

    let mut out = String::new();
    out.push_str(&header(spec));
    out.push_str(&format!(
        r#"use crucible_fuzzer::*;
use anchor_lang::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::rc::Rc;

// IDL-generated types. Drop the IDL at idls/{prog}.json before building.
crucible_idl_gen::declare_fuzz_program!("idls/{prog}.json");
use {prog}::instruction;
use {prog}::accounts;

"#
    ));

    emit_fixture_struct(&mut out, spec, &fixture);
    out.push('\n');
    emit_fixture_impl(&mut out, spec, &fixture)?;
    out.push('\n');
    emit_invariant_fn(&mut out, spec, &fixture);

    out.push_str("\n// ---- GENERATED BY QEDGEN — DO NOT EDIT BELOW THIS LINE ----\n");
    Ok(out)
}

fn header(spec: &ParsedSpec) -> String {
    let fp = crate::fingerprint::compute_fingerprint(spec);
    let hash = fp
        .file_hashes
        .get("fuzz/src/main.rs")
        .cloned()
        .unwrap_or_default();
    let mut s = crate::banner::banner(None, &hash);
    s.push_str("//\n");
    s.push_str("// Crucible coverage-guided fuzz harness for the spec.\n");
    s.push_str("//\n");
    s.push_str("// Each `action_*` method is mutated as a typed Action variant by the\n");
    s.push_str("// fuzzer. `invariant_test` is checked after every dispatched action.\n");
    s.push_str("// fuzz_assert! sets a thread-local violation flag instead of panicking,\n");
    s.push_str("// so the loop breaks gracefully and the input is recorded as a crash.\n");
    s.push_str("//\n");
    s.push_str("// To run:\n");
    s.push_str("//   cd fuzz/<program>/\n");
    s.push_str("//   crucible run <program> invariant_test\n");
    s.push_str("// ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ----\n");
    s.push_str("#![allow(unused_imports, unused_variables, dead_code)]\n\n");
    s
}

fn fixture_name(spec: &ParsedSpec) -> String {
    let raw: &str = if spec.program_name.is_empty() {
        "Program"
    } else {
        spec.program_name.as_str()
    };
    format!("{}Fixture", crate::codegen::to_pascal_case(raw))
}

fn emit_fixture_struct(out: &mut String, spec: &ParsedSpec, fixture: &str) {
    out.push_str("/// Fixture state. Includes Crucible test infrastructure plus shadow\n");
    out.push_str("/// fields mirroring spec state — invariants read from these instead of\n");
    out.push_str("/// from LiteSVM accounts directly so the body translation matches the\n");
    out.push_str("/// proptest / Kani backends.\n");
    out.push_str("#[derive(Clone)]\n");
    out.push_str(&format!("struct {fixture} {{\n"));
    out.push_str("    ctx: TestContext,\n");
    out.push_str("    program_id: Pubkey,\n");

    // Signing identities — derive from auth-cited handlers + named PDAs.
    let signers = collect_signer_idents(spec);
    for sig in &signers {
        out.push_str(&format!("    {sig}: Rc<Keypair>,\n"));
    }

    // Shadow fields for mutable state — read after each action.
    let state_fields = rust_codegen_util::resolve_state_fields(spec);
    let mutable_fields = rust_codegen_util::mutable_fields(state_fields);
    for (fname, ftype) in &mutable_fields {
        let rust_ty = map_simple_type(ftype);
        out.push_str(&format!("    {fname}: {rust_ty},\n"));
    }

    out.push_str("}\n");
}

/// Map a DSL type to its Rust shadow type. v0 handles only primitives + Pubkey;
/// compound types (records, sum types, Map) fall back to `()` with a TODO so
/// the user knows the field is unshadowed.
fn map_simple_type(dsl_type: &str) -> &'static str {
    match dsl_type {
        "U8" => "u8",
        "U16" => "u16",
        "U32" => "u32",
        "U64" => "u64",
        "U128" => "u128",
        "I8" => "i8",
        "I16" => "i16",
        "I32" => "i32",
        "I64" => "i64",
        "I128" => "i128",
        "Pubkey" => "Pubkey",
        "Bool" => "bool",
        _ => "() /* TODO: compound type shadow not yet supported */",
    }
}

fn collect_signer_idents(spec: &ParsedSpec) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for h in &spec.handlers {
        if let Some(who) = &h.who {
            seen.insert(who.clone());
        }
        for acc in &h.accounts {
            if acc.is_signer {
                seen.insert(acc.name.clone());
            }
        }
    }
    seen.into_iter().collect()
}

fn emit_fixture_impl(out: &mut String, spec: &ParsedSpec, fixture: &str) -> Result<()> {
    let prog = spec_program_name(spec);
    let signers = collect_signer_idents(spec);

    out.push_str("#[fuzz_fixture]\n");
    out.push_str(&format!("impl {fixture} {{\n"));

    // ── setup() ──────────────────────────────────────────────────────────
    out.push_str("    pub fn setup() -> Self {\n");
    out.push_str("        let mut ctx = TestContext::new();\n");
    out.push_str(&format!("        let program_id = {prog}::ID;\n"));
    out.push_str(&format!(
        "        ctx.add_program(&program_id, \"../../target/deploy/{prog}.so\")\n"
    ));
    out.push_str("            .unwrap();\n");
    for sig in &signers {
        out.push_str(&format!("        let {sig} = Rc::new(Keypair::new());\n"));
        out.push_str(&format!(
            "        ctx.create_account()\n            .pubkey({sig}.pubkey())\n            .lamports(100_000_000_000)\n            .owner(system_program::ID)\n            .create()\n            .unwrap();\n"
        ));
    }

    let state_fields = rust_codegen_util::resolve_state_fields(spec);
    let mutable_fields = rust_codegen_util::mutable_fields(state_fields);

    out.push_str("        Self {\n");
    out.push_str("            ctx,\n");
    out.push_str("            program_id,\n");
    for sig in &signers {
        out.push_str(&format!("            {sig},\n"));
    }
    for (fname, ftype) in &mutable_fields {
        let init = match map_simple_type(ftype) {
            "Pubkey" => "Pubkey::default()".to_string(),
            "bool" => "false".to_string(),
            t if t.starts_with("()") => "()".to_string(),
            _ => "0".to_string(),
        };
        out.push_str(&format!("            {fname}: {init},\n"));
    }
    out.push_str("        }\n    }\n\n");

    // ── action_* per handler ─────────────────────────────────────────────
    for h in &spec.handlers {
        emit_action_fn(out, spec, h)?;
        out.push('\n');
    }

    out.push_str("}\n");
    Ok(())
}

fn emit_action_fn(out: &mut String, spec: &ParsedSpec, op: &ParsedHandler) -> Result<()> {
    out.push_str(&format!(
        "    /// {} → action variant. Bodies for non-trivial\n",
        op.name
    ));
    out.push_str("    /// `accounts::X { ... }` literals fall through as todo!() — fill\n");
    out.push_str("    /// via `qedgen codegen --fill` once that hook lands for Crucible.\n");

    // Build param list with #[range] hints when bounds are inferable.
    let mut params = String::new();
    for (pname, ptype) in &op.takes_params {
        let rust_ty = map_simple_type(ptype);
        let range_attr = infer_range_attr(spec, ptype);
        if !range_attr.is_empty() {
            params.push_str(&format!("        {range_attr}\n"));
        }
        params.push_str(&format!("        {pname}: {rust_ty},\n"));
    }

    out.push_str(&format!(
        "    pub fn action_{}(\n        &mut self,\n{}    ) -> bool {{\n",
        op.name, params
    ));

    // Body — the Anchor `.call(...).accounts(...).send()` chain. Account
    // context comes from the spec's `accounts` block when present; v0
    // emits `todo!()` for the accounts struct (agent-fill) because the
    // Anchor accounts struct field naming is richer than we carry.
    let ix_name = pascal_case(&op.name);
    let arg_inits: String = op
        .takes_params
        .iter()
        .map(|(n, _)| format!("{n}, "))
        .collect();
    out.push_str("        let outcome = self.ctx.program(self.program_id)\n");
    out.push_str(&format!(
        "            .call(instruction::{ix_name} {{ {arg_inits}}})\n"
    ));
    out.push_str(&format!(
        "            .accounts(todo!(\"agent-fill: accounts::{ix_name} {{ ... }} from spec accounts block\"))\n"
    ));

    // Signers: take from `auth X` on the handler.
    if let Some(who) = &op.who {
        out.push_str(&format!("            .signers(&[&self.{who}])\n"));
    }
    out.push_str("            .send();\n");

    // Post-call: shadow state sync. v0 emits a structured comment because
    // syncing requires knowing the on-chain account struct shape — also
    // agent-fill once the hook lands.
    if !op.effects.is_empty() {
        out.push_str("        if outcome.is_success() {\n");
        out.push_str("            // TODO: sync shadow state from the on-chain account here.\n");
        out.push_str("            // For each effect declared in the spec, copy the post-state\n");
        out.push_str("            // field into the matching self.<field>. Example pattern:\n");
        out.push_str(
            "            //   let acc = self.ctx.read_anchor_account::<StateAcct>(&pda).unwrap();\n",
        );
        for (field, _kind, _rhs) in &op.effects {
            out.push_str(&format!("            //   self.{field} = acc.{field};\n"));
        }
        out.push_str("        }\n");
    }

    out.push_str("        outcome.is_success()\n");
    out.push_str("    }\n");
    Ok(())
}

/// Infer a `#[range(lo..hi)]` annotation for a handler param when the
/// spec carries a constant upper bound for the param's type. v0
/// heuristic: scan declared constants for one whose name matches
/// `MAX_<TYPE_TAG>` or `<TYPE_TAG>_MAX` and use it as the upper bound.
/// Falls back to "" (no annotation) — Crucible defaults to the type's
/// full range with boundary-biased mutation.
fn infer_range_attr(_spec: &ParsedSpec, _ptype: &str) -> String {
    // v0: no inference; the user can add #[range(..)] manually after gen.
    // v0.1+ can lift bounds from `requires p <= MAX` or `where` clauses.
    String::new()
}

/// snake_case → PascalCase (used for Anchor `instruction::Foo` / `accounts::Foo`).
fn pascal_case(s: &str) -> String {
    let mut out = String::new();
    let mut upper_next = true;
    for c in s.chars() {
        if c == '_' {
            upper_next = true;
        } else if upper_next {
            out.push(c.to_ascii_uppercase());
            upper_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn emit_invariant_fn(out: &mut String, spec: &ParsedSpec, fixture: &str) {
    let linked: Vec<&ParsedInvariant> = spec
        .invariants
        .iter()
        .filter(|i| {
            i.rust_expr
                .as_ref()
                .map(|r| !check::rust_expr_is_unsupported(r))
                .unwrap_or(false)
        })
        .filter(|i| {
            spec.handlers
                .iter()
                .any(|h| h.invariants.contains(&i.name) || h.establishes.contains(&i.name))
        })
        .collect();

    let props_with_expr: Vec<&ParsedProperty> = spec
        .properties
        .iter()
        .filter(|p| {
            p.rust_expression
                .as_ref()
                .map(|r| !check::rust_expr_is_unsupported(r))
                .unwrap_or(false)
        })
        .collect();

    out.push_str("#[invariant_test]\n");
    out.push_str(&format!("fn invariant_test(fixture: &mut {fixture}) {{\n"));

    if linked.is_empty() && props_with_expr.is_empty() {
        out.push_str("    // No spec invariants or properties with a Rust-renderable body.\n");
        out.push_str(
            "    // Add `invariant <name> : <expr>` or `property <name> { expr ... preserved_by ... }`\n",
        );
        out.push_str(
            "    // to the spec, then regenerate — Crucible will check it after every action.\n",
        );
    }

    for inv in &linked {
        let Some(rust) = inv.rust_expr.as_deref() else {
            continue;
        };
        let body = sanitize_body_for_fixture(rust);
        out.push_str(&format!(
            "    // Invariant: {}{}\n",
            inv.name,
            inv.lean_expr
                .as_deref()
                .map(|le| format!(" — {le}"))
                .unwrap_or_default()
        ));
        out.push_str(&format!(
            "    fuzz_assert!({body}, \"invariant {} violated\");\n",
            inv.name
        ));
    }

    for prop in &props_with_expr {
        let Some(rust) = prop.rust_expression.as_deref() else {
            continue;
        };
        let body = sanitize_body_for_fixture(rust);
        out.push_str(&format!(
            "    // Property: {}{}\n",
            prop.name,
            prop.expression
                .as_deref()
                .map(|e| format!(" — {e}"))
                .unwrap_or_default()
        ));
        out.push_str(&format!(
            "    fuzz_assert!({body}, \"property {} violated\");\n",
            prop.name
        ));
    }

    out.push_str("}\n");
}

/// The body strings produced by `translate_property_to_rust` (invariants)
/// and AST-rendered Rust (properties) reference `s.<field>`. The Crucible
/// invariant_test gets a `fixture` binding instead — rewrite the prefix.
fn sanitize_body_for_fixture(rust: &str) -> String {
    // Replace `s.` with `fixture.` only at token boundaries — i.e. when
    // the `s` starts a new identifier. Prior char must not be alphanumeric
    // or `_` (otherwise it's a longer ident ending in `s`) AND not `.`
    // (otherwise it's a nested field access like `foo.s.bar`).
    let mut out = String::new();
    let bytes = rust.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let at_start = i == 0;
        let after_break = i > 0
            && !(bytes[i - 1].is_ascii_alphanumeric()
                || bytes[i - 1] == b'_'
                || bytes[i - 1] == b'.');
        if (at_start || after_break)
            && i + 1 < bytes.len()
            && bytes[i] == b's'
            && bytes[i + 1] == b'.'
        {
            out.push_str("fixture.");
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chumsky_adapter::parse_str;

    const MINIMAL_SPEC: &str = r#"spec Counter
program_id "11111111111111111111111111111111"

const MAX_COUNT = 100

type State
  | Active of { count : U64 }

type Error
  | E

invariant count_bounded :
  state.count <= MAX_COUNT

handler increment : State.Active -> State.Active {
  permissionless
  invariant count_bounded
  requires state.count < MAX_COUNT
  effect { count := count + 1 }
}
"#;

    #[test]
    fn emits_cargo_toml_with_pinned_crucible_deps() {
        let spec = parse_str(MINIMAL_SPEC).expect("parse");
        let toml = emit_cargo_toml(&spec);
        assert!(toml.contains("name = \"counter_fuzz\""));
        assert!(toml.contains("crucible-fuzzer"));
        assert!(toml.contains("crucible-test-context"));
        assert!(toml.contains("[features]\ninvariant_test = []"));
        assert!(toml.contains("[workspace]"));
        // Workspace must be empty (isolates Solana/Anchor version chain).
        assert!(toml.contains("[workspace]\n\n[dependencies]"));
    }

    #[test]
    fn emits_fixture_with_state_shadow_fields() {
        let spec = parse_str(MINIMAL_SPEC).expect("parse");
        let mut out = String::new();
        emit_fixture_struct(&mut out, &spec, "CounterFixture");
        assert!(out.contains("#[derive(Clone)]"));
        assert!(out.contains("struct CounterFixture {"));
        assert!(out.contains("ctx: TestContext,"));
        assert!(out.contains("program_id: Pubkey,"));
        assert!(out.contains("count: u64,"));
    }

    #[test]
    fn emits_action_fn_per_handler() {
        let spec = parse_str(MINIMAL_SPEC).expect("parse");
        let mut out = String::new();
        emit_fixture_impl(&mut out, &spec, "CounterFixture").expect("emit");
        assert!(out.contains("#[fuzz_fixture]"));
        assert!(out.contains("impl CounterFixture {"));
        assert!(out.contains("pub fn setup() -> Self"));
        assert!(out.contains("pub fn action_increment(\n        &mut self,\n    ) -> bool"));
        // todo!() agent-fill site for the accounts struct literal
        assert!(out.contains("todo!(\"agent-fill: accounts::Increment"));
    }

    #[test]
    fn emits_invariant_test_with_fuzz_assert() {
        let spec = parse_str(MINIMAL_SPEC).expect("parse");
        let mut out = String::new();
        emit_invariant_fn(&mut out, &spec, "CounterFixture");
        assert!(out.contains("#[invariant_test]"));
        assert!(out.contains("fn invariant_test(fixture: &mut CounterFixture)"));
        assert!(out.contains("fuzz_assert!"));
        // Body is rewritten to fixture-relative — the comment line above
        // retains the original Lean form for human readability, but the
        // assertion line itself must reference fixture.
        let fuzz_assert_line = out
            .lines()
            .find(|l| l.contains("fuzz_assert!"))
            .expect("fuzz_assert! line present");
        assert!(
            fuzz_assert_line.contains("fixture.count"),
            "fuzz_assert! must reference fixture.count, got: {fuzz_assert_line}"
        );
        assert!(
            !fuzz_assert_line.contains(" s."),
            "raw `s.` must not survive into the Crucible assertion body: {fuzz_assert_line}"
        );
    }

    #[test]
    fn sbpf_spec_errors_early() {
        // Any spec with `pragma sbpf` should be refused — Crucible v2.18
        // ships Anchor-only. We synthesise a minimal ParsedSpec rather
        // than rely on the parser accepting a stub sBPF spec.
        let mut spec = ParsedSpec::default();
        spec.program_name = "SbpfProg".into();
        spec.pragmas.push("sbpf".into());
        spec.handlers.push(crate::check::ParsedHandler {
            name: "transfer".into(),
            ..synthetic_handler()
        });
        let tmp = std::env::temp_dir().join(format!("qedgen-crucible-{}", std::process::id()));
        let err = generate(&spec, &tmp).expect_err("sBPF spec should error");
        assert!(format!("{err:#}").contains("Anchor"));
    }

    fn synthetic_handler() -> crate::check::ParsedHandler {
        crate::check::ParsedHandler {
            name: "noop".into(),
            doc: None,
            who: None,
            on_account: None,
            pre_status: None,
            post_status: None,
            takes_params: vec![],
            guard_str: None,
            guard_str_rust: None,
            aborts_if: vec![],
            requires: vec![],
            ensures: vec![],
            modifies: None,
            let_bindings: vec![],
            aborts_total: false,
            permissionless: false,
            effects: vec![],
            accounts: vec![],
            transfers: vec![],
            emits: vec![],
            invariants: vec![],
            establishes: vec![],
            properties: vec![],
            calls: vec![],
        }
    }

    #[test]
    fn pascal_case_converts_snake() {
        assert_eq!(pascal_case("initialize"), "Initialize");
        assert_eq!(pascal_case("update_pool"), "UpdatePool");
        assert_eq!(pascal_case("a_b_c"), "ABC");
    }

    #[test]
    fn spec_name_snake_cases() {
        let mut spec = ParsedSpec::default();
        spec.program_name = "PercolatorRiskEngine".into();
        assert_eq!(spec_program_name(&spec), "percolator_risk_engine");
        spec.program_name = "escrow-split".into();
        assert_eq!(spec_program_name(&spec), "escrow_split");
    }

    #[test]
    fn sanitize_body_rewrites_s_prefix_at_token_boundary() {
        assert_eq!(
            sanitize_body_for_fixture("s.count <= 100"),
            "fixture.count <= 100"
        );
        assert_eq!(
            sanitize_body_for_fixture("s.a + s.b < s.c"),
            "fixture.a + fixture.b < fixture.c"
        );
        // Should not touch identifiers that happen to start with 's.'
        assert_eq!(
            sanitize_body_for_fixture("fixture.s.nested"),
            "fixture.s.nested"
        );
    }
}
