//! Cluster schema for the scaffold-to-spec interview (v2.19 M1).
//!
//! A "cluster" is a group of findings that lift to a single candidate spec
//! clause — the unit the auditor subagent asks the user about during the
//! interview. Many `pinocchio_unchecked_account_load` findings whose SAFETY
//! comments all reference "owner" collapse into one `account_owner_check`
//! cluster with `evidence_count = N`; the user answers one question to
//! ratify or reject the whole family.
//!
//! The vocabulary is **runtime-agnostic**: `ClusterKind` is the same set of
//! 14 variants for Pinocchio, Anchor, Native, and Quasar/codegen. Per-runtime
//! proto-clause extractors map their site shapes to these kinds; downstream
//! emission (prompts file, spec text) doesn't care which runtime produced
//! the cluster.
//!
//! Schema is v3 of the probe envelope. Findings remain at v2 shape; clusters
//! are an additive field gated behind `--emit-spec-candidates`.

// Constructors land incrementally across M1.3 (Pinocchio extractor), M1.4
// (algorithm), M1.5 (prompts writer). Lift this allow once those land.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// One ratification unit — a candidate spec clause derived from one or more
/// findings, presented to the user as a single interview question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    /// Deterministic hash of `(kind, scope, normalized_clause_text)`. Stable
    /// across runs — re-running the probe on an unchanged program produces
    /// the same `id`. Suppression rules and resumed-interview state key off
    /// this.
    pub id: String,
    /// Which spec-clause family this cluster belongs to. Drives the
    /// `suggested_syntax` template and the `writes_on_*` routing.
    pub kind: ClusterKind,
    /// Where the clause applies: program-wide invariant or per-handler.
    /// Promoted to `Program` when ≥3 handlers share the same normalized
    /// clause; otherwise `Handler(name)`.
    pub scope: ClusterScope,
    /// Back-pointers to the findings this cluster aggregates. Lets the
    /// auditor cross-reference cluster decisions with individual findings
    /// during write-up.
    pub finding_ids: Vec<String>,
    /// Number of findings rolled into this cluster. Surfaced to the user
    /// in the interview as "N sites assume X" — finding-count is the most
    /// load-bearing piece of evidence.
    pub evidence_count: usize,
    /// How sure we are the clause is real. Function of `(evidence_count,
    /// SAFETY-text match, cross-handler convergence)`. `High` clusters lead
    /// the interview; `Low` may be auto-dropped under a future suppression
    /// rule.
    pub confidence: Confidence,
    /// Human-readable summary of the candidate clause. Shown in the
    /// interview header.
    pub proto_clause_text: String,
    /// Verbatim `.qedspec` syntax for the accepted clause. M1 string-concats
    /// this into the spec file; M2 round-trips it through the AST.
    pub suggested_syntax: String,
    /// Pre-rendered markdown for the interview prompts file. Includes the
    /// header, the proto-clause text, and the option checkboxes. The
    /// auditor subagent concatenates these across all clusters into
    /// `.qed/audit/<ts>/interview.md`.
    pub question_md: String,
    /// Routing for the four interview outcomes. Each value is a logical
    /// destination key the prompts reader consults to dispatch the
    /// accepted/narrowed/rejected/bug clauses. Keys are documented in
    /// SCOPING-v2.19-scaffold-to-spec.md §4.
    pub writes_on_accept: String,
    pub writes_on_narrow: String,
    pub writes_on_reject: String,
    pub writes_on_bug: String,
}

/// The 14 production cluster kinds. Same vocabulary across all runtimes;
/// per-runtime extractors decide which detected site shapes lift to each
/// kind. See `docs/prds/SCOPING-v2.19-scaffold-to-spec.md` §3 for the
/// detection-to-kind table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterKind {
    /// `requires acc.owner == self_program_id` or program-wide
    /// `invariant owner_locked_writes`. Triggers from Pinocchio `_unchecked`
    /// loads with SAFETY-owner claims, Anchor `AccountInfo` for typed
    /// accounts, Native missing-owner-check sites.
    AccountOwnerCheck,
    /// `requires acc.is_initialized`. Triggers from `_unchecked` loads
    /// claiming an init precondition, Native handlers reading account data
    /// without an init guard.
    AccountInitCheck,
    /// Handler `auth X` clause or `permissionless` marker. Triggers from
    /// missing-signer findings across runtimes.
    AccountSignerCheck,
    /// `requires acc is .Variant` discriminator / type-tag check. Triggers
    /// from discriminator-collision sites and Anchor `AccountInfo` typed
    /// against a strongly-typed account family.
    AccountTypeTagCheck,
    /// `requires acc_a != acc_b` — aliasing prevention. Triggers from
    /// mutable-borrow-aliasing sites (Pinocchio `borrow_mut_*_unchecked`
    /// pairs, Anchor missing `has_one` constraint pairs).
    AccountDistinct,
    /// Effect uses `+=` (checked-by-default v2.7 G3) rather than `+=?`
    /// (wrapping). Triggers from raw `+`/`-` on amount/lamport fields,
    /// `set_amount(amount() + x)` patterns.
    ArithmeticNoOverflow,
    /// `requires amount <= bound` — caller-side value bound. Triggers from
    /// overflow sites where the implicit precondition is "amount fits in
    /// some pre-checked domain" (e.g. mint supply).
    ArithmeticBoundPre,
    /// `pda name [seeds]` with bump enforcement. Triggers from
    /// `create_program_address` (non-canonical), missing `bump` keyword in
    /// Anchor `seeds = [...]`.
    PdaCanonicalDerivation,
    /// Seed list includes a distinguishing field (e.g. caller pubkey).
    /// Triggers from shared-seed sites across handler families that don't
    /// differentiate by user/resource.
    PdaSeedUniqueness,
    /// Handler `State.Uninit -> State.Init` transition + `establishes`
    /// clause. Triggers from init-without-is-initialized sites.
    LifecycleOneShot,
    /// State-machine transitions declared in the spec's `type State` ADT.
    /// Triggers from re-init / close-without-zero-discriminator patterns.
    LifecycleMonotonic,
    /// `transfers { … }` or `call Interface.handler(...)` clause pinning
    /// the target program ID. Triggers from unvalidated `invoke_signed`,
    /// `AccountInfo`-typed program accounts.
    CpiProgramPin,
    /// `transfers { from X to Y authority Z }` with explicit direction.
    /// Triggers from CPI calls where source/destination/authority order
    /// is ambiguous in source.
    CpiAccountDirection,
    /// Cross-handler composition: caller establishes callee's `requires`.
    /// Triggers from batch-dispatch patterns (the p-token / cf136e7^ case),
    /// any handler dispatching to a fn that delegates ownership/precondition
    /// to its caller.
    DispatchCallerEstablishesCalleeRequires,
}

/// Where a cluster's clause applies in the emitted spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
pub enum ClusterScope {
    /// Program-wide invariant (top-level `invariant N`). Promoted when ≥3
    /// handlers share the normalized clause.
    Program,
    /// Handler-local `requires` / `ensures` / `establishes`. Carries the
    /// handler name so the spec emitter knows where to attach the clause.
    Handler(String),
}

/// Confidence in the cluster's correctness. Drives interview ordering and
/// future suppression rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl ClusterKind {
    /// Canonical snake_case identifier — used in the cluster ID hash and in
    /// per-runtime extractor mapping tables.
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterKind::AccountOwnerCheck => "account_owner_check",
            ClusterKind::AccountInitCheck => "account_init_check",
            ClusterKind::AccountSignerCheck => "account_signer_check",
            ClusterKind::AccountTypeTagCheck => "account_type_tag_check",
            ClusterKind::AccountDistinct => "account_distinct",
            ClusterKind::ArithmeticNoOverflow => "arithmetic_no_overflow",
            ClusterKind::ArithmeticBoundPre => "arithmetic_bound_pre",
            ClusterKind::PdaCanonicalDerivation => "pda_canonical_derivation",
            ClusterKind::PdaSeedUniqueness => "pda_seed_uniqueness",
            ClusterKind::LifecycleOneShot => "lifecycle_one_shot",
            ClusterKind::LifecycleMonotonic => "lifecycle_monotonic",
            ClusterKind::CpiProgramPin => "cpi_program_pin",
            ClusterKind::CpiAccountDirection => "cpi_account_direction",
            ClusterKind::DispatchCallerEstablishesCalleeRequires => {
                "dispatch_caller_establishes_callee_requires"
            }
        }
    }
}

impl ClusterScope {
    /// Canonical scope identifier for ID hashing and prompts-file routing.
    /// Program → "program"; Handler(name) → "handler:<name>".
    pub fn as_key(&self) -> String {
        match self {
            ClusterScope::Program => "program".to_string(),
            ClusterScope::Handler(n) => format!("handler:{}", n),
        }
    }
}

/// Intermediate form a per-runtime extractor emits before clustering.
/// One `ProtoClause` per (finding, candidate-clause) pair — a single site
/// with a multi-claim SAFETY comment can produce multiple ProtoClauses (one
/// per claim). M1.4's algorithm groups these into final `Cluster` entries.
#[derive(Debug, Clone)]
pub struct ProtoClause {
    /// Which spec-clause family this proto-clause belongs to.
    pub kind: ClusterKind,
    /// Handler the finding lives in. M1.4 may promote scope to Program when
    /// ≥3 handlers contribute proto-clauses of the same kind.
    pub handler: String,
    /// Back-pointer to the originating `Finding::id`. M1.4 collects these
    /// into the final `Cluster::finding_ids`.
    pub finding_id: String,
    /// The raw text the extractor classified (typically the SAFETY-comment
    /// clause, or the site expression for non-comment-driven cases).
    /// Stored for richer normalization in v2.20; v1 algorithm groups solely
    /// on `(kind, scope)`.
    pub evidence_text: String,
}

// ============================================================================
// Clustering algorithm (M1.4)
// ============================================================================

/// Promotion threshold — when a `ClusterKind`'s proto-clauses come from at
/// least this many distinct handlers, the kind is promoted from per-handler
/// scope to one consolidated program-wide cluster.
///
/// 3 is the smallest value that distinguishes "happens in a few places" from
/// "is a program-wide pattern." Below 3, per-handler clusters give the user
/// finer-grained control. Tunable based on dogfood feedback.
const PROGRAM_SCOPE_PROMOTION_THRESHOLD: usize = 3;

/// Confidence cut-offs: an evidence count of 5+ is `High`, 2-4 is `Medium`,
/// 1 is `Low`. Calibrated against the Pinocchio p-token catalogue (~64
/// unchecked-load findings collapse to 4-6 High clusters); revisit after
/// M3/M4 dogfood on real Anchor/Native programs.
const CONFIDENCE_HIGH_MIN_EVIDENCE: usize = 5;
const CONFIDENCE_MEDIUM_MIN_EVIDENCE: usize = 2;

/// The clustering algorithm: lifts a `Vec<ProtoClause>` from any
/// per-runtime extractor into a `Vec<Cluster>` ready for the prompts-file
/// writer.
///
/// Algorithm (v1 — naive but deterministic):
///
/// 1. Group proto-clauses by `(kind, handler)`.
/// 2. For each kind, count distinct contributing handlers.
/// 3. If the count meets `PROGRAM_SCOPE_PROMOTION_THRESHOLD`, emit one
///    program-scope cluster aggregating all proto-clauses of that kind.
/// 4. Otherwise, emit one handler-scope cluster per `(kind, handler)`
///    group.
/// 5. Generate deterministic IDs, confidence scores, and template-driven
///    rendering fields for each cluster.
///
/// Output ordering is stable: clusters are sorted by `(scope priority,
/// kind, scope key)` so re-running the algorithm produces the same JSON
/// envelope byte-for-byte.
pub fn cluster_protos(protos: Vec<ProtoClause>) -> Vec<Cluster> {
    use std::collections::{BTreeMap, BTreeSet};

    // Group by (kind, handler). BTreeMap preserves iteration order.
    let mut by_key: BTreeMap<(ClusterKind, String), Vec<ProtoClause>> = BTreeMap::new();
    for p in protos {
        by_key
            .entry((p.kind, p.handler.clone()))
            .or_default()
            .push(p);
    }

    // Per-kind handler set drives scope promotion.
    let mut handlers_per_kind: BTreeMap<ClusterKind, BTreeSet<String>> = BTreeMap::new();
    for (k, h) in by_key.keys() {
        handlers_per_kind.entry(*k).or_default().insert(h.clone());
    }
    let promote: BTreeSet<ClusterKind> = handlers_per_kind
        .iter()
        .filter(|(_, hs)| hs.len() >= PROGRAM_SCOPE_PROMOTION_THRESHOLD)
        .map(|(k, _)| *k)
        .collect();

    let mut clusters = Vec::new();

    // First pass: emit per-handler clusters for kinds NOT promoted to
    // program scope.
    for ((kind, handler), group) in &by_key {
        if promote.contains(kind) {
            continue;
        }
        let scope = ClusterScope::Handler(handler.clone());
        clusters.push(build_cluster(*kind, scope, group.iter()));
    }

    // Second pass: emit one program-scope cluster per promoted kind.
    for kind in &promote {
        let all: Vec<&ProtoClause> = by_key
            .iter()
            .filter(|((k, _), _)| k == kind)
            .flat_map(|(_, group)| group.iter())
            .collect();
        clusters.push(build_cluster(*kind, ClusterScope::Program, all.into_iter()));
    }

    // Stable output order: program-scope first (broader claims surface
    // before per-handler), then per-kind alphabetical, then per-scope
    // alphabetical.
    clusters.sort_by(|a, b| {
        let scope_priority = |s: &ClusterScope| match s {
            ClusterScope::Program => 0,
            ClusterScope::Handler(_) => 1,
        };
        scope_priority(&a.scope)
            .cmp(&scope_priority(&b.scope))
            .then(a.kind.as_str().cmp(b.kind.as_str()))
            .then(a.scope.as_key().cmp(&b.scope.as_key()))
    });

    clusters
}

/// Build a single cluster from a `(kind, scope, proto-clauses)` triple.
fn build_cluster<'a, I>(kind: ClusterKind, scope: ClusterScope, protos: I) -> Cluster
where
    I: Iterator<Item = &'a ProtoClause>,
{
    let mut finding_ids: Vec<String> = protos.map(|p| p.finding_id.clone()).collect();
    finding_ids.sort();
    finding_ids.dedup();
    let evidence_count = finding_ids.len();
    let confidence = score_confidence(evidence_count);
    let template = render_template(kind, &scope, evidence_count);
    let id = compute_cluster_id(kind, &scope);

    Cluster {
        id,
        kind,
        scope,
        finding_ids,
        evidence_count,
        confidence,
        proto_clause_text: template.proto_text,
        suggested_syntax: template.syntax,
        question_md: template.question,
        writes_on_accept: template.writes_on_accept,
        writes_on_narrow: template.writes_on_narrow,
        writes_on_reject: ".qed/plan/scoping.md".to_string(),
        writes_on_bug: ".qed/findings/".to_string(),
    }
}

fn score_confidence(evidence_count: usize) -> Confidence {
    if evidence_count >= CONFIDENCE_HIGH_MIN_EVIDENCE {
        Confidence::High
    } else if evidence_count >= CONFIDENCE_MEDIUM_MIN_EVIDENCE {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Deterministic cluster ID: `c-<8hex>-<kind>-<scope>`. Stable across
/// re-runs since we hash the kind + scope alone — evidence counts and
/// finding IDs change as the program evolves, but the cluster *identity*
/// (this specific candidate clause at this specific scope) does not.
fn compute_cluster_id(kind: ClusterKind, scope: &ClusterScope) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"qedgen-cluster-v1\n");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(scope.as_key().as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    format!("c-{}-{}-{}", &hex[..8], kind.as_str(), scope.as_key())
}

/// Per-(kind, scope) rendering: the text the user sees in the interview
/// plus the `.qedspec` syntax stub that gets concatenated into the
/// emitted spec on accept.
struct TemplateRender {
    proto_text: String,
    syntax: String,
    question: String,
    writes_on_accept: String,
    writes_on_narrow: String,
}

fn render_template(kind: ClusterKind, scope: &ClusterScope, n: usize) -> TemplateRender {
    let handler_name = match scope {
        ClusterScope::Program => None,
        ClusterScope::Handler(h) => Some(h.as_str()),
    };
    match kind {
        ClusterKind::AccountOwnerCheck => match scope {
            ClusterScope::Program => TemplateRender {
                proto_text: "Accounts whose owner ≠ self_program_id are read-only".into(),
                syntax: indent_spec(
                    "invariant owner_locked_writes\n  forall a in accounts: a.owner \
                     != self_program_id implies preserved(a.data) and preserved(a.lamports)\n",
                ),
                question: render_question(
                    "owner_locked_writes",
                    "_unchecked load",
                    n,
                    scope,
                    "program-wide invariant",
                ),
                writes_on_accept: "spec.invariants".into(),
                writes_on_narrow: "spec.handlers.*.requires".into(),
            },
            ClusterScope::Handler(h) => TemplateRender {
                proto_text: format!("Handler `{}` expects account.owner == self_program_id", h),
                syntax: format!(
                    "  // (added to handler {h}) — owner check on touched accounts\n  \
                     requires <account>.owner == self_program_id else Unauthorized\n"
                ),
                question: render_question(
                    "owner_check",
                    "_unchecked load",
                    n,
                    scope,
                    "per-handler precondition",
                ),
                writes_on_accept: format!("spec.handlers.{}.requires", h),
                writes_on_narrow: format!("spec.handlers.{}.requires", h),
            },
        },
        ClusterKind::AccountInitCheck => template_with_handler(
            "accounts_initialized_before_use",
            "Accounts are initialized before being read or written",
            "  forall a in accounts: a is initialized\n",
            "requires <account>.is_initialized else AccountNotInitialized",
            handler_name,
            n,
            "_unchecked load",
        ),
        ClusterKind::AccountSignerCheck => template_with_handler(
            "authority_signs_state_change",
            "Authority signs every handler that mutates state",
            "  -- modelled per-handler via `auth <name>`; no top-level invariant emitted\n",
            "auth <authority>",
            handler_name,
            n,
            "missing-signer",
        ),
        ClusterKind::AccountTypeTagCheck => template_with_handler(
            "account_type_tag_checked",
            "Accounts are loaded only after their type discriminator is checked",
            "  forall a in accounts: a is .<ExpectedVariant>\n",
            "requires <account> is .<ExpectedVariant> else InvalidAccountType",
            handler_name,
            n,
            "type-tag-free deserialization",
        ),
        ClusterKind::AccountDistinct => template_with_handler(
            "distinct_account_aliases",
            "Distinct account roles bind to distinct AccountInfo references",
            "  -- emitted per-handler via `requires acc_a != acc_b`\n",
            "requires <acc_a> != <acc_b> else AliasingAccounts",
            handler_name,
            n,
            "aliasing-borrow",
        ),
        ClusterKind::ArithmeticNoOverflow => match scope {
            ClusterScope::Program => TemplateRender {
                proto_text: "Token-amount and lamport arithmetic is checked (no wrap, no saturate)"
                    .into(),
                syntax: "// (rendered as per-effect `+=` / `-=` checked ops in handlers below)\n"
                    .into(),
                question: render_question(
                    "checked_arithmetic",
                    "unchecked arithmetic",
                    n,
                    scope,
                    "checked-by-default semantics",
                ),
                writes_on_accept: "spec.handlers.*.effects.op".into(),
                writes_on_narrow: "spec.handlers.<H>.effects.op".into(),
            },
            ClusterScope::Handler(h) => TemplateRender {
                proto_text: format!("Handler `{}` uses checked arithmetic on amounts/lamports", h),
                syntax: format!(
                    "  // (added to handler {h}) — use `+=` / `-=` (checked) on amount fields,\n  \
                     // not `+=?` (wrapping) or `+=!` (saturating). v2.7 G3 semantics.\n"
                ),
                question: render_question(
                    "checked_arithmetic",
                    "unchecked arithmetic",
                    n,
                    scope,
                    "per-handler checked operators",
                ),
                writes_on_accept: format!("spec.handlers.{}.effects.op", h),
                writes_on_narrow: format!("spec.handlers.{}.effects.op", h),
            },
        },
        ClusterKind::ArithmeticBoundPre => template_with_handler(
            "amount_within_domain_bound",
            "Amount parameters fall within a pre-checked domain (e.g. mint supply)",
            "  -- typically rendered as a per-handler `requires amount <= <bound>`\n",
            "requires amount <= <bound> else AmountTooLarge",
            handler_name,
            n,
            "raw arithmetic on caller-supplied amount",
        ),
        ClusterKind::PdaCanonicalDerivation => template_with_handler(
            "canonical_pda_derivation",
            "PDAs use canonical (find_program_address) bumps",
            "  pda <name> [<seeds>]\n",
            "pda <name> [<seeds>]  // canonical derivation",
            handler_name,
            n,
            "create_program_address",
        ),
        ClusterKind::PdaSeedUniqueness => template_with_handler(
            "pda_seed_distinguishes_users",
            "PDA seeds include a caller-distinguishing field",
            "  pda <name> [<scope>, caller.pubkey]\n",
            "pda <name> [<scope>, caller.pubkey]",
            handler_name,
            n,
            "shared PDA seeds",
        ),
        ClusterKind::LifecycleOneShot => template_with_handler(
            "init_is_one_shot",
            "Init-style handlers transition the account from uninitialized to initialized",
            "  // declared via `handler init : State.Uninit -> State.Init`\n",
            "/// `init` is a one-shot State.Uninit -> State.Init transition",
            handler_name,
            n,
            "init-without-is-initialized",
        ),
        ClusterKind::LifecycleMonotonic => template_with_handler(
            "lifecycle_progress_monotonic",
            "Lifecycle states progress monotonically (no replays)",
            "  // declared via the State ADT + per-handler pre/post\n",
            "/// State transitions monotone — no handler maps a Closed state back to Open",
            handler_name,
            n,
            "re-init / replay",
        ),
        ClusterKind::CpiProgramPin => template_with_handler(
            "cpi_program_pinned",
            "CPI program accounts are pinned to expected program IDs",
            "  // declared via `transfers { … }` or `call Interface.handler(...)`\n",
            "/// CPI to <program>: declare via `transfers` or `call Interface.handler(...)`",
            handler_name,
            n,
            "invoke_signed",
        ),
        ClusterKind::CpiAccountDirection => template_with_handler(
            "cpi_direction_explicit",
            "CPI source / destination / authority order is explicit",
            "  transfers {\n    from <src> to <dst> amount <amount> authority <auth>\n  }\n",
            "transfers { from <src> to <dst> amount <amount> authority <auth> }",
            handler_name,
            n,
            "CPI argument order",
        ),
        ClusterKind::DispatchCallerEstablishesCalleeRequires => template_with_handler(
            "dispatcher_establishes_callee_preconditions",
            "Dispatchers establish callee `requires` before dispatching",
            "  // declared via `call Interface.handler(...)` with explicit `requires` mapping\n",
            "/// Dispatcher must establish each callee's `requires` (no runtime-gate trust)",
            handler_name,
            n,
            "batch-mode dispatch",
        ),
    }
}

fn template_with_handler(
    invariant_name: &str,
    proto_text: &str,
    program_syntax_body: &str,
    handler_syntax: &str,
    handler: Option<&str>,
    n: usize,
    site_label: &str,
) -> TemplateRender {
    match handler {
        None => TemplateRender {
            proto_text: proto_text.to_string(),
            syntax: format!("invariant {}\n{}", invariant_name, program_syntax_body),
            question: render_question(
                invariant_name,
                site_label,
                n,
                &ClusterScope::Program,
                "program-wide invariant",
            ),
            writes_on_accept: "spec.invariants".into(),
            writes_on_narrow: "spec.handlers.*.requires".into(),
        },
        Some(h) => TemplateRender {
            proto_text: format!("Handler `{}`: {}", h, proto_text),
            syntax: format!("  // (added to handler {})\n  {}\n", h, handler_syntax),
            question: render_question(
                invariant_name,
                site_label,
                n,
                &ClusterScope::Handler(h.to_string()),
                "per-handler precondition",
            ),
            writes_on_accept: format!("spec.handlers.{}.requires", h),
            writes_on_narrow: format!("spec.handlers.{}.requires", h),
        },
    }
}

/// Indent each non-empty line by two spaces so the suggested syntax slots
/// cleanly under a `spec ProgramName` declaration when concatenated by the
/// M1.8 emitter.
fn indent_spec(s: &str) -> String {
    s.lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("  {}", l)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Render the markdown prompt the user sees in the interview file.
/// Standardized layout: header → evidence summary → options as checkboxes.
fn render_question(
    label: &str,
    site_label: &str,
    n: usize,
    scope: &ClusterScope,
    summary: &str,
) -> String {
    let scope_phrase = match scope {
        ClusterScope::Program => "across the program".to_string(),
        ClusterScope::Handler(h) => format!("in handler `{}`", h),
    };
    let mut s = String::new();
    s.push_str(&format!("## {}\n\n", label));
    s.push_str(&format!(
        "{} {} site(s) {} imply this {}.\n\n",
        n, site_label, scope_phrase, summary
    ));
    s.push_str("- [ ] **accept** — emit the suggested clause into the spec\n");
    if matches!(scope, ClusterScope::Program) {
        s.push_str("- [ ] **narrow** — emit per-handler `requires` clauses instead\n");
    }
    s.push_str("- [ ] **reject** — over-claim; drop with rationale below\n");
    s.push_str("- [ ] **bug** — flag as missing enforcement (not a spec clause)\n");
    s.push_str("\n_notes:_\n\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm the v3 envelope shape — `kind` / `scope` / `confidence`
    /// serialize as snake_case strings, `scope` is internally-tagged with
    /// `kind` + `name` fields, and the optional `name` is omitted for
    /// `Program` scope.
    #[test]
    fn cluster_serializes_to_v3_envelope_shape() {
        let c = Cluster {
            id: "c-9f3a-account_owner_check-program".to_string(),
            kind: ClusterKind::AccountOwnerCheck,
            scope: ClusterScope::Program,
            finding_ids: vec!["51a8".to_string(), "f983".to_string()],
            evidence_count: 31,
            confidence: Confidence::High,
            proto_clause_text: "Accounts whose owner != self_program_id are read-only".into(),
            suggested_syntax: "invariant owner_locked_writes\n".into(),
            question_md: "## owner_locked_writes\n…".into(),
            writes_on_accept: "spec.invariants".into(),
            writes_on_narrow: "spec.handlers.*.requires".into(),
            writes_on_reject: ".qed/plan/scoping.md".into(),
            writes_on_bug: ".qed/findings/".into(),
        };
        let json = serde_json::to_value(&c).expect("serialize");
        assert_eq!(json["kind"], "account_owner_check");
        assert_eq!(json["confidence"], "high");
        assert_eq!(json["evidence_count"], 31);
        assert_eq!(json["scope"]["kind"], "program");
        assert!(
            json["scope"].get("name").is_none(),
            "Program scope must not carry a name; got {:?}",
            json["scope"]
        );
    }

    #[test]
    fn handler_scope_carries_name() {
        let c = Cluster {
            id: "c-1b2c-account_signer_check-handler:transfer".to_string(),
            kind: ClusterKind::AccountSignerCheck,
            scope: ClusterScope::Handler("process_transfer".into()),
            finding_ids: vec!["abc".into()],
            evidence_count: 1,
            confidence: Confidence::Medium,
            proto_clause_text: "".into(),
            suggested_syntax: "".into(),
            question_md: "".into(),
            writes_on_accept: "spec.handlers.process_transfer.auth".into(),
            writes_on_narrow: "spec.handlers.process_transfer.auth".into(),
            writes_on_reject: ".qed/plan/scoping.md".into(),
            writes_on_bug: ".qed/findings/".into(),
        };
        let json = serde_json::to_value(&c).expect("serialize");
        assert_eq!(json["scope"]["kind"], "handler");
        assert_eq!(json["scope"]["name"], "process_transfer");
    }

    #[test]
    fn kind_as_str_round_trips_all_fourteen() {
        // Compile-time exhaustive: if any variant is added without an
        // `as_str` arm, this test fails to build.
        let all = [
            ClusterKind::AccountOwnerCheck,
            ClusterKind::AccountInitCheck,
            ClusterKind::AccountSignerCheck,
            ClusterKind::AccountTypeTagCheck,
            ClusterKind::AccountDistinct,
            ClusterKind::ArithmeticNoOverflow,
            ClusterKind::ArithmeticBoundPre,
            ClusterKind::PdaCanonicalDerivation,
            ClusterKind::PdaSeedUniqueness,
            ClusterKind::LifecycleOneShot,
            ClusterKind::LifecycleMonotonic,
            ClusterKind::CpiProgramPin,
            ClusterKind::CpiAccountDirection,
            ClusterKind::DispatchCallerEstablishesCalleeRequires,
        ];
        let mut seen = std::collections::HashSet::new();
        for k in all {
            let s = k.as_str();
            assert!(!s.is_empty(), "{:?} has empty as_str", k);
            assert!(seen.insert(s), "{:?} collides with another variant's as_str = {}", k, s);
        }
        assert_eq!(seen.len(), 14, "expected 14 distinct cluster kinds");
    }

    #[test]
    fn scope_as_key_distinguishes_program_vs_handler() {
        assert_eq!(ClusterScope::Program.as_key(), "program");
        assert_eq!(
            ClusterScope::Handler("process_transfer".into()).as_key(),
            "handler:process_transfer"
        );
    }

    fn proto(kind: ClusterKind, handler: &str, finding_id: &str) -> ProtoClause {
        ProtoClause {
            kind,
            handler: handler.to_string(),
            finding_id: finding_id.to_string(),
            evidence_text: String::new(),
        }
    }

    #[test]
    fn promotes_to_program_scope_when_three_handlers_share_kind() {
        let protos = vec![
            proto(ClusterKind::AccountOwnerCheck, "transfer", "f1"),
            proto(ClusterKind::AccountOwnerCheck, "burn", "f2"),
            proto(ClusterKind::AccountOwnerCheck, "mint_to", "f3"),
        ];
        let clusters = cluster_protos(protos);
        assert_eq!(clusters.len(), 1, "expected one Program-scope cluster");
        assert_eq!(clusters[0].kind, ClusterKind::AccountOwnerCheck);
        assert_eq!(clusters[0].scope, ClusterScope::Program);
        assert_eq!(clusters[0].evidence_count, 3);
    }

    #[test]
    fn keeps_handler_scope_when_only_two_handlers_share_kind() {
        let protos = vec![
            proto(ClusterKind::AccountOwnerCheck, "transfer", "f1"),
            proto(ClusterKind::AccountOwnerCheck, "burn", "f2"),
        ];
        let clusters = cluster_protos(protos);
        assert_eq!(clusters.len(), 2, "expected two Handler-scope clusters");
        assert!(clusters
            .iter()
            .all(|c| matches!(c.scope, ClusterScope::Handler(_))));
    }

    #[test]
    fn deduplicates_finding_ids_within_a_cluster() {
        // Two proto-clauses from the same finding (e.g., SAFETY with two
        // claim words mapping to the same kind) should not double-count.
        let protos = vec![
            proto(ClusterKind::AccountOwnerCheck, "transfer", "f1"),
            proto(ClusterKind::AccountOwnerCheck, "transfer", "f1"),
        ];
        let clusters = cluster_protos(protos);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].evidence_count, 1);
        assert_eq!(clusters[0].finding_ids, vec!["f1"]);
    }

    #[test]
    fn cluster_id_is_deterministic_across_runs() {
        let protos1 = vec![
            proto(ClusterKind::AccountOwnerCheck, "transfer", "f1"),
            proto(ClusterKind::AccountOwnerCheck, "burn", "f2"),
            proto(ClusterKind::AccountOwnerCheck, "mint_to", "f3"),
        ];
        let protos2 = protos1.clone();
        let c1 = cluster_protos(protos1);
        let c2 = cluster_protos(protos2);
        assert_eq!(c1[0].id, c2[0].id);
    }

    #[test]
    fn cluster_id_independent_of_evidence_count() {
        // Identity = (kind, scope). A program evolving (gaining/losing
        // findings) should not change the cluster's ID — only its
        // evidence_count and confidence.
        let protos_few = vec![
            proto(ClusterKind::AccountOwnerCheck, "transfer", "f1"),
            proto(ClusterKind::AccountOwnerCheck, "burn", "f2"),
            proto(ClusterKind::AccountOwnerCheck, "mint_to", "f3"),
        ];
        let protos_many = {
            let mut v = protos_few.clone();
            v.extend([
                proto(ClusterKind::AccountOwnerCheck, "approve", "f4"),
                proto(ClusterKind::AccountOwnerCheck, "freeze", "f5"),
            ]);
            v
        };
        let id_few = cluster_protos(protos_few)[0].id.clone();
        let id_many = cluster_protos(protos_many)[0].id.clone();
        assert_eq!(id_few, id_many, "cluster ID must be scope-stable");
    }

    #[test]
    fn confidence_scales_with_evidence_count() {
        let one = cluster_protos(vec![proto(ClusterKind::AccountInitCheck, "h", "f1")]);
        assert_eq!(one[0].confidence, Confidence::Low);

        let three: Vec<_> = (1..=3)
            .map(|i| {
                proto(
                    ClusterKind::AccountInitCheck,
                    &format!("h{}", i),
                    &format!("f{}", i),
                )
            })
            .collect();
        // Three handlers promotes to Program scope; 3 evidence => Medium.
        let three_out = cluster_protos(three);
        assert_eq!(three_out[0].confidence, Confidence::Medium);

        let five: Vec<_> = (1..=5)
            .map(|i| {
                proto(
                    ClusterKind::AccountInitCheck,
                    &format!("h{}", i),
                    &format!("f{}", i),
                )
            })
            .collect();
        let five_out = cluster_protos(five);
        assert_eq!(five_out[0].confidence, Confidence::High);
    }

    #[test]
    fn output_order_is_stable_program_first_then_handler() {
        let protos = vec![
            proto(ClusterKind::AccountInitCheck, "h_alone", "f1"), // handler-scope (alone)
            proto(ClusterKind::AccountOwnerCheck, "transfer", "f2"),
            proto(ClusterKind::AccountOwnerCheck, "burn", "f3"),
            proto(ClusterKind::AccountOwnerCheck, "mint_to", "f4"), // promoted to Program
        ];
        let clusters = cluster_protos(protos);
        // First cluster must be Program-scope (AccountOwnerCheck).
        assert!(matches!(clusters[0].scope, ClusterScope::Program));
        assert_eq!(clusters[0].kind, ClusterKind::AccountOwnerCheck);
        // Subsequent clusters are Handler-scope.
        for c in &clusters[1..] {
            assert!(matches!(c.scope, ClusterScope::Handler(_)));
        }
    }

    #[test]
    fn rendered_template_includes_evidence_count_and_options() {
        let protos: Vec<_> = (1..=4)
            .map(|i| {
                proto(
                    ClusterKind::AccountOwnerCheck,
                    &format!("h{}", i),
                    &format!("f{}", i),
                )
            })
            .collect();
        let clusters = cluster_protos(protos);
        let c = &clusters[0];
        assert!(c.question_md.contains("**accept**"));
        assert!(c.question_md.contains("**reject**"));
        assert!(c.question_md.contains("**bug**"));
        // Program-scope clusters offer narrow → handler-level.
        assert!(c.question_md.contains("**narrow**"));
        // Evidence count is mentioned in the prose.
        assert!(c.question_md.contains("4"), "want '4' in {}", c.question_md);
    }

    #[test]
    fn handler_scope_writes_to_specific_handler_path() {
        let protos = vec![proto(ClusterKind::AccountOwnerCheck, "transfer", "f1")];
        let clusters = cluster_protos(protos);
        assert_eq!(clusters[0].writes_on_accept, "spec.handlers.transfer.requires");
    }

    #[test]
    fn empty_input_produces_empty_clusters() {
        assert!(cluster_protos(vec![]).is_empty());
    }
}
