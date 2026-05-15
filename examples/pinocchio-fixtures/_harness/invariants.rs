//! `_harness/invariants.rs` — assertion primitives that bracket
//! handler calls in Miri repros (v2.19 PRD G3).
//!
//! Miri catches *language-level* UB. Our probes target *program-level*
//! obligations. These primitives close the gap by capturing pre/post
//! state and asserting conservation / distinctness / write-ownership
//! invariants.

use super::state::GlobalState;

/// Lamport conservation: sum of lamports across the account set is
/// preserved across handler invocation, modulo `exempt_set` (e.g. the
/// fee payer or wrapped-SOL accounts where lamports flow with the
/// token amount).
pub fn assert_lamport_conservation(pre: &GlobalState, post: &GlobalState, exempt_set: &[[u8; 32]]) {
    let pre_sum = pre.lamport_sum_excluding(exempt_set);
    let post_sum = post.lamport_sum_excluding(exempt_set);
    assert_eq!(
        pre_sum, post_sum,
        "lamport conservation violated: pre={} post={} (delta {})",
        pre_sum,
        post_sum,
        (post_sum as i128) - (pre_sum as i128)
    );
}

/// Token conservation per mint: for each mint, the sum of `amount`
/// fields across token accounts of that mint is preserved.
pub fn assert_token_conservation_per_mint(pre: &GlobalState, post: &GlobalState) {
    for (mint, pre_sum) in &pre.token_sums_by_mint {
        let post_sum = post.token_sums_by_mint.get(mint).copied().unwrap_or(0);
        assert_eq!(
            *pre_sum, post_sum,
            "token conservation violated for mint {:?}: pre={} post={}",
            mint, pre_sum, post_sum
        );
    }
}

/// Sanity: no two accounts in the set share the same backing data
/// buffer pointer. Catches caller-side aliasing the handler relied
/// on `dup_flag` to prevent.
pub fn assert_distinct_data_buffers(account_ptrs: &[*const u8]) {
    for i in 0..account_ptrs.len() {
        for j in (i + 1)..account_ptrs.len() {
            assert_ne!(
                account_ptrs[i], account_ptrs[j],
                "accounts at positions {} and {} share a data buffer (aliasing)",
                i, j
            );
        }
    }
}

/// Every account mutated between pre and post must have been owned by
/// `program_id` at pre time. Catches handlers that write through an
/// `AccountInfo` they don't own.
pub fn assert_no_unowned_writes(pre: &GlobalState, post: &GlobalState, program_id: &[u8; 32]) {
    for (key, pre_entry) in &pre.accounts {
        let post_entry = match post.accounts.get(key) {
            Some(e) => e,
            None => continue,
        };
        if pre_entry.data == post_entry.data
            && pre_entry.lamports == post_entry.lamports
        {
            continue; // no mutation
        }
        assert_eq!(
            &pre_entry.owner, program_id,
            "handler wrote to account {:?} owned by {:?} (not program_id)",
            key, pre_entry.owner
        );
    }
}

/// Every write to a writable account requires a corresponding signer
/// in `signer_set` (or program-derived authority).
pub fn assert_signer_required_for_writes(
    pre: &GlobalState,
    post: &GlobalState,
    signer_set: &[[u8; 32]],
) {
    for (key, pre_entry) in &pre.accounts {
        let post_entry = match post.accounts.get(key) {
            Some(e) => e,
            None => continue,
        };
        if pre_entry.data == post_entry.data
            && pre_entry.lamports == post_entry.lamports
        {
            continue;
        }
        // Either the account itself is in signer_set, or one of the
        // signers covers it via program-derivation. We require the
        // simpler version here; PDA-authority chains are agent's job
        // to wire per-probe.
        assert!(
            signer_set.iter().any(|s| s == key),
            "write to {:?} but no signer in signer_set authorized it",
            key
        );
    }
}

/// Lifecycle monotonicity: the `state_field_offset` byte must
/// transition through `allowed_transitions` only.
pub fn assert_monotonic_lifecycle(
    pre: &GlobalState,
    post: &GlobalState,
    key: &[u8; 32],
    state_field_offset: usize,
    allowed_transitions: &[(u8, u8)],
) {
    let pre_entry = match pre.accounts.get(key) {
        Some(e) => e,
        None => return,
    };
    let post_entry = match post.accounts.get(key) {
        Some(e) => e,
        None => return,
    };
    let pre_state = pre_entry.data.get(state_field_offset).copied().unwrap_or(0);
    let post_state = post_entry.data.get(state_field_offset).copied().unwrap_or(0);
    if pre_state == post_state {
        return;
    }
    assert!(
        allowed_transitions.contains(&(pre_state, post_state)),
        "lifecycle transition {} -> {} not in allowed set",
        pre_state,
        post_state
    );
}
