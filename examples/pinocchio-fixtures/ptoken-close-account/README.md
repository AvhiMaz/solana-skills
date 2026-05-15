# ptoken-close-account fixture

Mirrors `solana-program/token/pinocchio/program/src/processor/close_account.rs`.
Exercises: `unchecked_account_load`, `unchecked_lamport_arith`,
`mutable_borrow_aliasing` (two `borrow_mut_*_unchecked` calls on
distinct accounts whose distinctness rests on a runtime check).

## Running

```bash
qedgen probe --program examples/pinocchio-fixtures/ptoken-close-account
```

Patterns to find:
- `src/close_account.rs:25` — `load_mut_unchecked` for source
- `src/close_account.rs:44` / `:45` — paired `borrow_mut_lamports_unchecked`
  whose lifetimes overlap (aliasing probe target)
- `src/close_account.rs:50` — `*destination_lamports = *destination_lamports + *source_lamports`
  with a stale SAFETY claim about rent-exempt cap

## Attribution

Synthesized fixture; pattern inspiration from upstream p-token. See
`NOTICE.md`.
