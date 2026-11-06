Tools and Utilities
-------------------

- `bitcoin-util getchainparams` now includes a `storage` object with
  `assumed_blockchain_gib` and `assumed_chain_state_gib`, the hardcoded disk
  space estimates (in GiB) that Bitcoin Core uses for the selected chain. Both
  are 0 when no estimate exists, as on regtest and custom signets.
