//! `_harness/state.rs` — capture per-account pre/post state for the
//! conservation primitives.

use std::collections::BTreeMap;

use super::account::SyntheticAccount;

#[derive(Debug, Clone)]
pub struct AccountEntry {
    pub lamports: u64,
    pub owner: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct GlobalState {
    pub accounts: BTreeMap<[u8; 32], AccountEntry>,
    pub token_sums_by_mint: BTreeMap<[u8; 32], u64>,
}

impl GlobalState {
    pub fn lamport_sum(&self) -> u64 {
        self.accounts.values().map(|a| a.lamports).sum()
    }

    pub fn lamport_sum_excluding(&self, exempt: &[[u8; 32]]) -> u64 {
        self.accounts
            .iter()
            .filter(|(k, _)| !exempt.contains(k))
            .map(|(_, a)| a.lamports)
            .sum()
    }
}

/// Snapshot the pre/post state of an account set. The token-amount
/// extraction reads SPL Token's offset-64 amount field — adjust per
/// fixture if the account shape differs.
pub fn capture_global_state(accounts: &[SyntheticAccount]) -> GlobalState {
    let mut g = GlobalState::default();
    for a in accounts {
        g.accounts.insert(
            a.key,
            AccountEntry {
                lamports: a.lamports,
                owner: a.owner,
                data: a.data.clone(),
            },
        );
        // Token-account heuristic: 165-byte data, offset 64..72 is amount.
        if a.data.len() == 165 {
            let mut amount_bytes = [0u8; 8];
            amount_bytes.copy_from_slice(&a.data[64..72]);
            let amount = u64::from_le_bytes(amount_bytes);
            // Mint at offset 0..32.
            let mut mint = [0u8; 32];
            mint.copy_from_slice(&a.data[0..32]);
            *g.token_sums_by_mint.entry(mint).or_insert(0) =
                g.token_sums_by_mint.get(&mint).copied().unwrap_or(0).wrapping_add(amount);
        }
    }
    g
}
