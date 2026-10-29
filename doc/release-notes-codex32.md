Wallet
------

- `addhdkey` has a new `codex32` option that adds the HD key for a BIP 93
  codex32 secret, or for exactly k codex32 shares of one secret. The key is the
  BIP 32 master key of the master seed they encode. A wallet backed up with
  codex32 shares can be restored into a new blank wallet like this, where the
  shares are read from standard input to keep them out of the shell history:

  ```
  bitcoin-cli -named createwallet wallet_name=restored blank=true
  bitcoin-cli -named -rpcwallet=restored -stdin addhdkey
  codex32=["ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t","ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr","ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm"]
  (press Ctrl-D)
  bitcoin-cli -named -rpcwallet=restored createwalletdescriptor type=bech32m hdkey=<xpub returned by addhdkey>
  bitcoin-cli -rpcwallet=restored rescanblockchain <block height when the wallet was created>
  ```

  Run `createwalletdescriptor` once for each address type the wallet used.
  codex32 strings do not record when the wallet was created, so without a
  known height `rescanblockchain` has to start from the genesis block.
