//! Fixture: minimal Pinocchio-shaped ATA create handler.
//!
//! Mirrors `solana-program/associated-token-account/pinocchio/program/src/processor/create.rs`.
//! Cross-program-invoke surface: calls System Program for account
//! creation and Token Program for initialization. The audit
//! obligations are: PDA derivation, position-based account access,
//! CPI parameter integrity.

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};

const TOKEN_PROGRAM_ID: Pubkey = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
    28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

pub fn process_create(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // Position-based dispatch — no #[derive(Accounts)] validating
    // layout.
    let payer = &accounts[0];
    let ata = &accounts[1];
    let wallet = &accounts[2];
    let mint = &accounts[3];
    let system_program = &accounts[4];
    let token_program = &accounts[5];

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Note: we *should* re-derive the ATA from
    // `find_program_address(&[wallet.key(), TOKEN_PROGRAM_ID, mint.key()],
    // program_id)` and compare to `ata.key()`. This fixture
    // intentionally OMITS that check — the audit should flag it as a
    // `missing_pda_verification` finding.

    // Build the System Program CreateAccount CPI.
    let create_ix = Instruction {
        program_id: system_program.key(),
        accounts: &[
            AccountMeta::writable_signer(payer.key()),
            AccountMeta::writable(ata.key()),
        ],
        data: &[0u8; 52], // CreateAccount discriminator + space + owner
    };

    // SAFETY: ata is a writable PDA derived from wallet + mint.
    unsafe {
        invoke(&create_ix, &[payer.clone(), ata.clone()])?;
    }

    // Build the Token Program InitializeAccount CPI.
    let init_ix = Instruction {
        program_id: &TOKEN_PROGRAM_ID,
        accounts: &[
            AccountMeta::writable(ata.key()),
            AccountMeta::readonly(mint.key()),
            AccountMeta::readonly(wallet.key()),
        ],
        data: &[1u8], // InitializeAccount discriminator
    };

    unsafe {
        invoke(&init_ix, &[ata.clone(), mint.clone(), wallet.clone()])?;
    }

    Ok(())
}
