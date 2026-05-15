//! `_harness/adversarial.rs` — input-negation primitives the v2.19
//! Miri reproducers use to weaponize SAFETY-comment clauses (PRD G1).
//!
//! Each SAFETY-clause shape has a corresponding `*_setup()` fn that
//! builds the `Vec<SyntheticAccount>` + instruction data exercising
//! the negated precondition. The audit subagent picks the strategy
//! based on the SAFETY-clause → strategy table in
//! `references/probes/pinocchio/stale_safety_comment.md`.

use super::account::SyntheticAccount;

pub const TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
    28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// G1 negation: "owner == program_id" → swap owner for a Pubkey we
/// generate at random.
pub fn foreign_owner(amount: u64) -> Vec<SyntheticAccount> {
    let attacker = [42u8; 32]; // not TOKEN_PROGRAM_ID
    let src_key = [1u8; 32];
    let dst_key = [2u8; 32];
    let auth_key = [3u8; 32];

    vec![
        SyntheticAccount::new(src_key, attacker, 1_000, 165)
            .with_data(build_token_account_data(amount, &auth_key)),
        SyntheticAccount::new(dst_key, TOKEN_PROGRAM_ID, 1_000, 165)
            .with_data(build_token_account_data(0, &auth_key)),
        SyntheticAccount::new(auth_key, SYSTEM_PROGRAM_ID, 1_000_000_000, 0).signed(),
    ]
}

/// G1 negation: "data.len() >= N" → buffer shorter than required.
pub fn short_buffer(required_len: usize) -> Vec<SyntheticAccount> {
    let src_key = [1u8; 32];
    let dst_key = [2u8; 32];
    let short = required_len.saturating_sub(8);

    vec![
        SyntheticAccount::new(src_key, TOKEN_PROGRAM_ID, 1_000, short)
            .with_data(vec![0u8; short]),
        SyntheticAccount::new(dst_key, TOKEN_PROGRAM_ID, 1_000, 165)
            .with_data(build_token_account_data(0, &[0u8; 32])),
    ]
}

/// G1 negation: "X != Y" (distinctness) → pass the same AccountInfo
/// at two positions. The buffer is shared; Miri's aliasing tracker
/// flags any double-mut-borrow.
pub fn swap_position(amount: u64) -> Vec<SyntheticAccount> {
    let key = [9u8; 32];
    let auth_key = [3u8; 32];

    // Two entries pointing at the same underlying account key — the
    // input buffer's `dup_flag` would normally indicate this, but we
    // skip the dup marker so the handler treats them as distinct
    // until it dereferences.
    vec![
        SyntheticAccount::new(key, TOKEN_PROGRAM_ID, 10_000, 165)
            .with_data(build_token_account_data(amount, &auth_key)),
        SyntheticAccount::new(key, TOKEN_PROGRAM_ID, 10_000, 165)
            .with_data(build_token_account_data(amount, &auth_key)),
        SyntheticAccount::new(auth_key, SYSTEM_PROGRAM_ID, 1_000_000_000, 0).signed(),
    ]
}

/// G1 negation: "X is initialized" → init flag byte is zero.
pub fn uninit_init_flag() -> Vec<SyntheticAccount> {
    let src_key = [1u8; 32];
    let mut data = build_token_account_data(0, &[0u8; 32]);
    // Pinocchio Account state byte index 108 = AccountState (0 = Uninit).
    if data.len() > 108 {
        data[108] = 0;
    }
    vec![SyntheticAccount::new(src_key, TOKEN_PROGRAM_ID, 1_000, data.len()).with_data(data)]
}

/// G1 negation: "lamports >= amount" → set lamports below amount.
pub fn short_balance(amount: u64) -> Vec<SyntheticAccount> {
    let src_key = [1u8; 32];
    let dst_key = [2u8; 32];
    let auth_key = [3u8; 32];

    vec![
        SyntheticAccount::new(src_key, TOKEN_PROGRAM_ID, amount.saturating_sub(1), 165)
            .with_data(build_token_account_data(amount, &auth_key)),
        SyntheticAccount::new(dst_key, TOKEN_PROGRAM_ID, 1_000, 165)
            .with_data(build_token_account_data(0, &auth_key)),
        SyntheticAccount::new(auth_key, SYSTEM_PROGRAM_ID, 1_000_000_000, 0).signed(),
    ]
}

/// G1 negation: "amount <= u64::MAX bound" → set source.amount = MAX
/// and request +1 to trigger wrap.
pub fn oversized_amount() -> Vec<SyntheticAccount> {
    let src_key = [1u8; 32];
    let dst_key = [2u8; 32];
    let auth_key = [3u8; 32];

    vec![
        SyntheticAccount::new(src_key, TOKEN_PROGRAM_ID, 1_000, 165)
            .with_data(build_token_account_data(u64::MAX, &auth_key)),
        SyntheticAccount::new(dst_key, TOKEN_PROGRAM_ID, 1_000, 165)
            .with_data(build_token_account_data(u64::MAX - 1, &auth_key)),
        SyntheticAccount::new(auth_key, SYSTEM_PROGRAM_ID, 1_000_000_000, 0).signed(),
    ]
}

/// G1 negation: "single mutable borrow" → alias the data buffer.
pub fn alias_buffer() -> Vec<SyntheticAccount> {
    // Same key, same owner — two AccountInfo views over the same data
    // region. The handler should reject (dup_flag would be set in a
    // real runtime invocation; absent here to expose the aliasing
    // path).
    let key = [11u8; 32];
    let auth_key = [3u8; 32];

    vec![
        SyntheticAccount::new(key, TOKEN_PROGRAM_ID, 10_000, 165)
            .with_data(build_token_account_data(100, &auth_key)),
        SyntheticAccount::new(key, TOKEN_PROGRAM_ID, 10_000, 165)
            .with_data(build_token_account_data(100, &auth_key)),
        SyntheticAccount::new(auth_key, SYSTEM_PROGRAM_ID, 1_000_000_000, 0).signed(),
    ]
}

/// Build the 165-byte SPL Token Account layout (mint, owner, amount,
/// delegate, state, is_native, delegated_amount, close_authority).
/// Minimal enough for the Pinocchio handler to parse via load_mut.
fn build_token_account_data(amount: u64, owner: &[u8; 32]) -> Vec<u8> {
    let mut data = vec![0u8; 165];
    // mint (32 bytes) — leave zero
    // owner (32 bytes) at offset 32
    data[32..64].copy_from_slice(owner);
    // amount (8 bytes) at offset 64
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate option byte at 72 — 0 = None
    // state byte at offset 108: 1 = Initialized
    data[108] = 1;
    data
}
