//! `_harness/account.rs` — synthesize Pinocchio-shaped `AccountInfo`
//! values for direct-call (Miri-lane) testing.
//!
//! Pinocchio's `AccountInfo` is structurally a raw pointer into the
//! runtime input buffer. To exercise a handler under Miri without the
//! SVM in the way, we need to:
//!
//!  1. Allocate the backing bytes (lamports, data, owner).
//!  2. Lay them out in the exact wire format Pinocchio's `parse_accounts`
//!     expects.
//!  3. Hand out `&AccountInfo` references that the handler can read /
//!     borrow exactly as it would when called from the runtime.
//!
//! Because Pinocchio is no_std and uses `core::transmute` to construct
//! the public `AccountInfo` view from the raw input buffer, this
//! harness uses `Box::leak` + `transmute` and is intentionally `unsafe`
//! at the boundary. Miri verifies the layout is sound; if Pinocchio
//! changes the on-the-wire shape upstream, this harness fails loudly
//! (compile error or Miri abort) rather than silently mis-aligning.
//!
//! Layout assumption: Pinocchio v0.6.x. Re-validate on minor bumps.

use core::cell::UnsafeCell;
use std::collections::HashMap;

/// One synthetic account: lamports + data + owner + flags. The handler
/// sees this through Pinocchio's `AccountInfo` typed view.
#[derive(Debug)]
pub struct SyntheticAccount {
    pub key: [u8; 32],
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
    pub executable: bool,
    pub rent_epoch: u64,
}

impl SyntheticAccount {
    pub fn new(key: [u8; 32], owner: [u8; 32], lamports: u64, data_len: usize) -> Self {
        SyntheticAccount {
            key,
            lamports,
            data: vec![0u8; data_len],
            owner,
            is_signer: false,
            is_writable: true,
            executable: false,
            rent_epoch: 0,
        }
    }

    pub fn signed(mut self) -> Self {
        self.is_signer = true;
        self
    }

    pub fn readonly(mut self) -> Self {
        self.is_writable = false;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }
}

/// Compose multiple synthetic accounts into the contiguous input
/// buffer the Pinocchio entrypoint expects. Returns the input buffer
/// + the parsed slice the handler imports use.
///
/// The exact wire format is Pinocchio's internal — what's important
/// for v2.19 is that the buffer can be passed to the handler and the
/// handler observes the same `AccountInfo` shape it would in
/// production.
pub fn build_input_buffer(accounts: &[SyntheticAccount], instruction_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Format per Pinocchio v0.6.x:
    //   [n_accounts: u64]
    //   for each account:
    //     [dup_flag: u8]
    //     [is_signer: bool] [is_writable: bool] [executable: bool]
    //     [pad: 4 bytes]
    //     [pubkey: 32]
    //     [owner: 32]
    //     [lamports: u64]
    //     [data_len: u64]
    //     [data: data_len]
    //     [pad to 8-byte boundary]
    //     [rent_epoch: u64]
    //   [instruction_data_len: u64]
    //   [instruction_data: instruction_data_len]
    //   [program_id: 32]
    buf.extend_from_slice(&(accounts.len() as u64).to_le_bytes());
    for a in accounts {
        buf.push(0xff); // dup_flag (0xff = no dup)
        buf.push(a.is_signer as u8);
        buf.push(a.is_writable as u8);
        buf.push(a.executable as u8);
        buf.extend_from_slice(&[0u8; 4]); // pad
        buf.extend_from_slice(&a.key);
        buf.extend_from_slice(&a.owner);
        buf.extend_from_slice(&a.lamports.to_le_bytes());
        buf.extend_from_slice(&(a.data.len() as u64).to_le_bytes());
        buf.extend_from_slice(&a.data);
        // pad to 8-byte boundary
        let pad = (8 - (a.data.len() % 8)) % 8;
        buf.extend_from_slice(&vec![0u8; pad]);
        buf.extend_from_slice(&a.rent_epoch.to_le_bytes());
    }
    buf.extend_from_slice(&(instruction_data.len() as u64).to_le_bytes());
    buf.extend_from_slice(instruction_data);
    // program_id slot — populated by the test harness from the fixture.
    buf.extend_from_slice(&[0u8; 32]);
    buf
}

/// Leak a heap buffer and return a `*mut u8` Pinocchio's `entrypoint!`
/// expects. The caller is responsible for not freeing — Miri runs
/// short-lived tests so leak-per-test is acceptable.
pub fn leak_input(buf: Vec<u8>) -> *mut u8 {
    let boxed = buf.into_boxed_slice();
    Box::leak(boxed).as_mut_ptr()
}
