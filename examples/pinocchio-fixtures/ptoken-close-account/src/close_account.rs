//! Fixture: minimal Pinocchio-shaped `process_close_account`.
//!
//! Mirrors `solana-program/token/pinocchio/program/src/processor/close_account.rs`.
//! Sweeps source lamports to destination and resets the state byte to
//! `Uninitialized`. The audit obligations are: aliasing (src != dst),
//! lamport conservation, lifecycle monotonicity.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_error::ProgramError,
};
use pinocchio_token::state::Account;

pub fn process_close_account(accounts: &[AccountInfo]) -> ProgramResult {
    let [source_account_info, destination_account_info, owner_info, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if source_account_info.key() == destination_account_info.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // SAFETY: source and destination are distinct; the runtime
    // guarantees no aliasing via dup_flag.
    let source_account = unsafe {
        Account::load_mut_unchecked(source_account_info.borrow_mut_data_unchecked())?
    };

    if !owner_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if source_account.owner() != owner_info.key() {
        return Err(ProgramError::IllegalOwner);
    }
    if source_account.amount() != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Sweep source lamports into destination.
    let source_lamports = unsafe { source_account_info.borrow_mut_lamports_unchecked() };
    let destination_lamports =
        unsafe { destination_account_info.borrow_mut_lamports_unchecked() };

    // **SAFETY: this addition cannot overflow because `destination_lamports`
    // was previously below rent-exempt and `source_lamports` is at most
    // u64::MAX / 2.** (Stale claim — there is no rent-exempt cap on
    // destination here.)
    *destination_lamports = *destination_lamports + *source_lamports;
    *source_lamports = 0;

    // Mark closed: write state byte. In real p-token this is a typed
    // state-byte write; here we just zero the data buffer through the
    // unchecked accessor.
    let source_data = unsafe { source_account_info.borrow_mut_data_unchecked() };
    for byte in source_data.iter_mut() {
        *byte = 0;
    }

    Ok(())
}
