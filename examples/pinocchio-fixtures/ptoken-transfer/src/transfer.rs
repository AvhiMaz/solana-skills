//! Fixture: minimal Pinocchio-shaped `process_transfer` mirroring
//! `solana-program/token/pinocchio/program/src/processor/shared/transfer.rs`.
//!
//! Hand-authored to match the patterns called out in PRD v2.19
//! "What real Pinocchio looks like":
//!
//!   - Line 60ish: unchecked load of `source_account` (init-check
//!     skipped via `_unchecked` suffix; SAFETY claim chain).
//!   - Line ~95: `destination_account.set_amount(...)` with raw +
//!     (no checked_add).
//!   - Line ~100: `*source_lamports -= amount` with comment claiming
//!     a bound that is enforced for token-amounts but not lamports.
//!
//! Real p-token is far larger; this fixture is scoped to the three
//! patterns the v2.19 success bar tests.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use pinocchio_token::state::Account;

/// Transfer `amount` tokens from `source_account_info` to
/// `destination_account_info`.
///
/// Authority is `authority_info` (must be signer). Spec-side this is
/// a single-handler program; in real p-token it composes with mint
/// validation and delegate semantics.
pub fn process_transfer(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let [source_account_info, mint_info, destination_account_info, authority_info, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(instruction_data[..8].try_into().unwrap());

    if amount == 0 {
        return Ok(());
    }

    // Load source — the unsuffixed `load_mut` validates the
    // initialization flag.
    let source_account = unsafe {
        Account::load_mut(source_account_info.borrow_mut_data_unchecked())?
    };

    // Validate authority is signer.
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if source_account.owner() != authority_info.key() {
        return Err(ProgramError::IllegalOwner);
    }

    // SAFETY: the account is guaranteed to be initialized and different
    // than `source_account_info`; it was also already validated to be a
    // token account.
    let destination_account = unsafe {
        Account::load_mut_unchecked(destination_account_info.borrow_mut_data_unchecked())?
    };

    // Update amounts. **The amount of a token account is always within
    // the range of the mint supply (`u64`), so this addition cannot
    // overflow.**  (This comment is the canonical-stale-claim probe
    // target.)
    destination_account.set_amount(destination_account.amount() + amount);
    source_account.set_amount(source_account.amount() - amount);

    // If this is a native-mint account, sync lamports with the token
    // amount. **The `lamports` on the account is always greater than
    // `amount`, so this subtraction cannot underflow.**  (Token-amount
    // bound; does NOT cover lamports on native accounts.)
    if source_account.is_native() {
        let source_lamports = unsafe { source_account_info.borrow_mut_lamports_unchecked() };
        *source_lamports -= amount;

        let destination_lamports =
            unsafe { destination_account_info.borrow_mut_lamports_unchecked() };
        *destination_lamports = destination_lamports.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
    }

    Ok(())
}
