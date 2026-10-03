#!/usr/bin/env python3
# Copyright (c) 2021-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a basic M-of-N multisig setup between multiple people using descriptor wallets and PSBTs, as well as a signing flow.

This is meant to be documentation as much as functional tests, so it is kept as simple and readable as possible.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
)

from test_framework.descriptors import descsum_create


class WalletMultisigDescriptorPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-keypool=100"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def _get_xpub(wallet):
        """Derive an xpub at the BIP 87 account path m/87h/1h/0h using `derivehdkey`."""
        hdkey_info = wallet.derivehdkey("m/87h/1h/0h")
        # Keep all key origin information (master key fingerprint and all derivation steps) for proper support of hardware devices
        # See section 'Key origin identification' in 'doc/descriptors.md' for more details...
        return f"{hdkey_info['origin']}{hdkey_info['xpub']}/<0;1>/*"

    @staticmethod
    def _check_psbt(psbt, to, value, multisig):
        """Helper function for any of the N participants to check the psbt with decodepsbt and verify it is OK before signing."""
        decoded = multisig.decodepsbt(psbt)
        amount = 0
        for psbt_out in decoded["outputs"]:
            address = psbt_out["script"]["address"]
            assert_equal(multisig.getaddressinfo(address)["ischange"], address != to)
            if address == to:
                amount += psbt_out["amount"]
        assert_approx(amount, float(value), vspan=0.001)

    def import_multisig(self, wallet, xpubs):
        """The multisig is created by importing the following descriptor. It contains only xpubs, so every participant imports the same string.
        A participant's wallet recognizes its own xpub and uses the matching private key, so the resulting wallet can also sign."""
        desc = descsum_create(f"wsh(sortedmulti({self.M},{','.join(xpubs)}))")
        self.log.debug(desc)
        result = wallet.importdescriptors([
            {
                "desc": desc,
                "active": True,
                "timestamp": "now",
            },
        ])
        assert all(r["success"] for r in result)

    def run_test(self):
        self.M = 2
        self.N = 3
        self.node = self.nodes[0]
        self.name = f"{self.M}_of_{self.N}_multisig"
        self.log.info(f"Testing {self.name}...")

        # Every participant creates a blank wallet and adds an HD key to it. The wallet has no singlesig descriptors,
        # so it can't accidentally be used for anything other than the multisig (for privacy reasons).
        participants = []
        for i in range(self.N):
            participant = self.node.get_wallet_rpc(self.node.createwallet(wallet_name=f"participant_{i}", blank=True)["name"])
            participant.addhdkey()
            participants.append(participant)

        self.log.info("Generate and exchange xpubs...")
        xpubs = [self._get_xpub(participant) for participant in participants]

        self.log.info("Every participant imports the same descriptor into their wallet to create the multisig...")
        for participant in participants:
            self.import_multisig(participant, xpubs)

        self.log.info("Anyone else, for example a coordinator who holds none of the keys, can import it into a watch-only wallet...")
        watch_only = self.node.get_wallet_rpc(self.node.createwallet(wallet_name=f"{self.name}_watch_only", blank=True, disable_private_keys=True)["name"])
        self.import_multisig(watch_only, xpubs)
        multisigs = participants + [watch_only]

        self.log.info("Check that every multisig wallet generates the same addresses...")
        for _ in range(10):  # we check that the first 10 generated addresses are the same for all multisig wallets
            receive_addresses = [multisig.getnewaddress() for multisig in multisigs]
            for address in receive_addresses:
                assert_equal(address, receive_addresses[0])
            change_addresses = [multisig.getrawchangeaddress() for multisig in multisigs]
            for address in change_addresses:
                assert_equal(address, change_addresses[0])

        self.log.info("Get a mature utxo to send to the multisig...")
        funder = self.node.get_wallet_rpc(self.node.createwallet(wallet_name="funder")["name"])
        self.generatetoaddress(self.node, 101, funder.getnewaddress())

        deposit_amount = 6.15
        multisig_receiving_address = participants[0].getnewaddress()
        self.log.info("Send funds to the resulting multisig receiving address...")
        funder.sendtoaddress(multisig_receiving_address, deposit_amount)
        self.generate(self.node, 1)
        for multisig in multisigs:
            assert_approx(multisig.getbalance(), deposit_amount, vspan=0.001)

        self.log.info("Send a transaction from the multisig!")
        recipient = self.node.get_wallet_rpc(self.node.createwallet(wallet_name="recipient")["name"])
        to = recipient.getnewaddress()
        value = 1
        self.log.info("First, make a sending transaction, created using `walletcreatefundedpsbt` (anyone can initiate this, including the watch-only wallet)...")
        psbt = watch_only.walletcreatefundedpsbt(inputs=[], outputs={to: value}, feeRate=0.00010)

        psbts = []
        self.log.info("Now at least M users check the psbt with decodepsbt and (if OK) signs it with walletprocesspsbt...")
        for m in range(self.M):
            self._check_psbt(psbt["psbt"], to, value, participants[m])
            partially_signed_psbt = participants[m].walletprocesspsbt(psbt["psbt"])
            assert_equal(partially_signed_psbt["complete"], False)
            psbts.append(partially_signed_psbt["psbt"])

        self.log.info("Finally, collect the signed PSBTs with combinepsbt, finalizepsbt, then broadcast the resulting transaction...")
        combined = watch_only.combinepsbt(psbts)
        self.log.debug(watch_only.analyzepsbt(combined))
        finalized = watch_only.finalizepsbt(combined)
        watch_only.sendrawtransaction(finalized["hex"])

        self.log.info("Check that balances are correct after the transaction has been included in a block.")
        self.generate(self.node, 1)
        assert_approx(watch_only.getbalance(), deposit_amount - value, vspan=0.001)
        assert_equal(recipient.getbalance(), value)

        self.log.info("Send another transaction from the multisig, this time with a daisy chained signing flow (one after another in series)!")
        psbt = participants[0].walletcreatefundedpsbt(inputs=[], outputs={to: value}, feeRate=0.00010)
        for m in range(self.M):
            self._check_psbt(psbt["psbt"], to, value, participants[m])
            psbt = participants[m].walletprocesspsbt(psbt["psbt"])
            assert_equal(psbt["complete"], m == self.M - 1)
        participants[0].sendrawtransaction(psbt["hex"])

        self.log.info("Check that balances are correct after the transaction has been included in a block.")
        self.generate(self.node, 1)
        assert_approx(watch_only.getbalance(), deposit_amount - (value * 2), vspan=0.001)
        assert_equal(recipient.getbalance(), value * 2)

        self.log.info("A participant who only kept a backup of their HD key can restore a wallet that signs for the multisig...")
        backup = [hdkey["xprv"] for hdkey in participants[self.N - 1].gethdkeys(private=True) if hdkey["has_private"]]
        assert_equal(len(backup), 1)
        restored = self.node.get_wallet_rpc(self.node.createwallet(wallet_name="participant_restored", blank=True)["name"])
        restored.addhdkey(backup[0])
        self.import_multisig(restored, xpubs)
        psbt = watch_only.walletcreatefundedpsbt(inputs=[], outputs={to: value}, feeRate=0.00010)
        psbt = participants[0].walletprocesspsbt(psbt["psbt"])
        assert_equal(psbt["complete"], False)
        psbt = restored.walletprocesspsbt(psbt["psbt"])
        assert_equal(psbt["complete"], True)
        watch_only.sendrawtransaction(psbt["hex"])
        self.generate(self.node, 1)
        assert_approx(watch_only.getbalance(), deposit_amount - (value * 3), vspan=0.001)
        assert_equal(recipient.getbalance(), value * 3)


if __name__ == "__main__":
    WalletMultisigDescriptorPSBTTest(__file__).main()
