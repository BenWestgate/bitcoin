Wallet
------

- `createwalletdescriptor` has a new `timestamp` option. It sets the creation
  time of the new descriptors and rescans the blockchain from that time, so a
  key restored with `addhdkey` finds its earlier transactions without a
  separate `rescanblockchain` call. Without the option, the descriptors get the
  current time and nothing is rescanned, as before.
