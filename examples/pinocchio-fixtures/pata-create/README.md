# pata-create fixture

Mirrors `solana-program/associated-token-account/pinocchio/program/src/processor/create.rs`.
Exercises: `position_based_account_without_type_tag`,
`missing_pda_verification`, CPI parameter integrity.

## Running

```bash
qedgen probe --program examples/pinocchio-fixtures/pata-create
```

Patterns to find:
- `src/create.rs:33-38` — position-based account access (`accounts[N]`)
  without ownership/type verification at each position
- *Implicit*: no `find_program_address` derivation for `ata` — the
  agent must spot the absence (handled by `missing_pda_verification`
  probe, which fires from the agent's CF read, not the CLI enumerator).
- `src/create.rs:51`, `:63` — CPI invokes through `unsafe` blocks with
  SAFETY claims

## Attribution

Synthesized fixture; pattern inspiration from upstream p-ata.
