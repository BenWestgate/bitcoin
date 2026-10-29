#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test restoring an HD key from BIP 93 codex32 strings with addhdkey."""

import hashlib
import hmac

from test_framework.address import byte_to_base58
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock

XPRV_VERSION = bytes.fromhex("0488ade4")
TPRV_VERSION = bytes.fromhex("04358394")

# BIP 93 test vectors 1 to 5: codex32 strings, the master seed and the master xprv
VECTOR_1 = {
    "secret": "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw",
    "seed": "318c6318c6318c6318c6318c6318c631",
    "xprv": "xprv9s21ZrQH143K3taPNekMd9oV5K6szJ8ND7vVh6fxicRUMDcChr3bFFzuxY8qP3xFFBL6DWc2uEYCfBFZ2nFWbAqKPhtCLRjgv78EZJDEfpL",
}
VECTOR_2 = {
    "a": "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
    "c": "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN",
    "d": "MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG",
    "secret": "MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW",
    "seed": "d1808e096b35b209ca12132b264662a5",
    "xprv": "xprv9s21ZrQH143K2NkobdHxXeyFDqE44nJYvzLFtsriatJNWMNKznGoGgW5UMTL4fyWtajnMYb5gEc2CgaKhmsKeskoi9eTimpRv2N11THhPTU",
}
VECTOR_3 = {
    "secret": "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln",
    "alternates": [
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2",
    ],
    "a": "ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t",
    "c": "ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr",
    "d": "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm",
    "e": "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9",
    "f": "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704",
    "seed": "ffeeddccbbaa99887766554433221100",
    "xprv": "xprv9s21ZrQH143K266qUcrDyYJrSG7KA3A7sE5UHndYRkFzsPQ6xwUhEGK1rNuyyA57Vkc1Ma6a8boVqcKqGNximmAe9L65WsYNcNitKRPnABd",
}
VECTOR_4 = {
    "secret": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
    "seed": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
    "xprv": "xprv9s21ZrQH143K3s41UCWxXTsU4TRrhkpD1t21QJETan3hjo8DP5LFdFcB5eaFtV8x6Y9aZotQyP8KByUjgLTbXCUjfu2iosTbMv98g8EQoqr",
}
VECTOR_5 = {
    "secret": "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK",
    "seed": "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9",
    "xprv": "xprv9s21ZrQH143K4UYT4rP3TZVKKbmRVmfRqTx9mG2xCy2JYipZbkLV8rwvBXsUbEv9KQiUD7oED1Wyi9evZzUn2rqK9skRgPkNaAzyw3YrpJN",
}
# BIP 93 test vectors 6 to 8 (no xprv is given for these)
VECTORS_6_7_8 = [
    ("ms10seedsqqqsyqcyq5rqwzqfpg9scrgwpugpzysn9vaqzzvs20xnl", "000102030405060708090a0b0c0d0e0f10111213"),
    ("ms10seedsyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdau84gz0632s0xs", "202122232425262728292a2b2c2d2e2f3031323334353637"),
    ("ms10seedsgpq5ys6yg4rywjzfff95cn2wfag9z5jn2324v46ct9d9hrcduqw8c3lccl", "404142434445464748494a4b4c4d4e4f505152535455565758595a5b"),
]


def master_xprv(seed_hex, version):
    """Serialize the BIP 32 master private key of a seed."""
    i = hmac.new(b"Bitcoin seed", bytes.fromhex(seed_hex), hashlib.sha512).digest()
    # depth, parent fingerprint and child number are all zero for a master key
    payload = version[1:] + bytes(9) + i[32:] + b"\x00" + i[:32]
    return byte_to_base58(payload, version[0])


class WalletCodex32Test(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.wallet_count = 0
        self.test_bip93_vectors()
        self.test_restore()
        self.test_restore_cli()
        self.test_invalid()
        self.test_wallet_state()

    def expected_xpub(self, seed_hex):
        """The regtest xpub of the master key for a seed."""
        tprv = master_xprv(seed_hex, TPRV_VERSION)
        desc = self.nodes[0].getdescriptorinfo(f"pkh({tprv})")["descriptor"]
        return desc[len("pkh("):desc.index(")")]

    def blank_wallet(self, **kwargs):
        self.wallet_count += 1
        name = f"codex32_{self.wallet_count}"
        self.nodes[0].createwallet(wallet_name=name, blank=True, **kwargs)
        return self.nodes[0].get_wallet_rpc(name)

    def add_codex32(self, strings):
        """Add the HD key for some codex32 strings to a new blank wallet and return its xpub."""
        wallet = self.blank_wallet()
        xpub = wallet.addhdkey(codex32=strings)["xpub"]
        wallet.unloadwallet()
        return xpub

    def test_bip93_vectors(self):
        self.log.info("Check that the master seed helper matches the BIP 93 xprvs")
        for vector in [VECTOR_1, VECTOR_2, VECTOR_3, VECTOR_4, VECTOR_5]:
            assert_equal(master_xprv(vector["seed"], XPRV_VERSION), vector["xprv"])

        self.log.info("Add HD keys from codex32 secrets")
        for vector in [VECTOR_1, VECTOR_2, VECTOR_3, VECTOR_4, VECTOR_5]:
            assert_equal(self.add_codex32([vector["secret"]]), self.expected_xpub(vector["seed"]))
        for secret, seed in VECTORS_6_7_8:
            assert_equal(self.add_codex32([secret]), self.expected_xpub(seed))

        self.log.info("Any choice of padding bits gives the same HD key")
        for secret in VECTOR_3["alternates"]:
            assert_equal(self.add_codex32([secret]), self.expected_xpub(VECTOR_3["seed"]))

        self.log.info("Add HD keys recovered from exactly k codex32 shares")
        v2_xpub = self.expected_xpub(VECTOR_2["seed"])
        assert_equal(self.add_codex32([VECTOR_2["a"], VECTOR_2["c"]]), v2_xpub)
        assert_equal(self.add_codex32([VECTOR_2["d"], VECTOR_2["a"]]), v2_xpub)
        assert_equal(self.add_codex32([VECTOR_2["c"].lower(), VECTOR_2["d"]]), v2_xpub)
        v3_xpub = self.expected_xpub(VECTOR_3["seed"])
        assert_equal(self.add_codex32([VECTOR_3["a"], VECTOR_3["c"], VECTOR_3["d"]]), v3_xpub)
        assert_equal(self.add_codex32([VECTOR_3["f"], VECTOR_3["e"], VECTOR_3["c"]]), v3_xpub)

    def test_restore(self):
        self.log.info("Restore a funded wallet from codex32 shares")
        node = self.nodes[0]
        def_wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.generatetoaddress(node, 101, def_wallet.getnewaddress())

        original = self.blank_wallet()
        xpub = original.addhdkey(codex32=[VECTOR_3["secret"]])["xpub"]
        original.createwalletdescriptor(type="bech32m", hdkey=xpub)
        birth_height = node.getblockcount()
        def_wallet.sendtoaddress(original.getnewaddress(address_type="bech32m"), 1)
        def_wallet.sendtoaddress(original.getnewaddress(address_type="bech32m"), 2)
        self.generate(node, 1)
        assert_equal(original.getbalance(), 3)

        restored = self.blank_wallet()
        assert_equal(restored.addhdkey(codex32=[VECTOR_3["c"], VECTOR_3["e"], VECTOR_3["a"]])["xpub"], xpub)
        restored.createwalletdescriptor(type="bech32m", hdkey=xpub)
        restored.rescanblockchain(birth_height)
        assert_equal(restored.getbalance(), 3)
        assert_equal(
            sorted(d["desc"] for d in restored.listdescriptors()["descriptors"]),
            sorted(d["desc"] for d in original.listdescriptors()["descriptors"]),
        )

    def test_restore_cli(self):
        if not self.is_cli_compiled():
            return
        self.log.info("Add an HD key from codex32 shares read by bitcoin-cli -stdin")
        wallet = self.blank_wallet()
        shares = f'codex32=["{VECTOR_2["a"]}","{VECTOR_2["c"]}"]'
        cli = self.nodes[0].cli(f"-rpcwallet={wallet.getwalletinfo()['walletname']}", "-named", "-stdin", input=shares)
        assert_equal(cli.addhdkey()["xpub"], self.expected_xpub(VECTOR_2["seed"]))

    def test_invalid(self):
        self.log.info("Reject invalid codex32 strings")
        wallet = self.blank_wallet()
        bad_checksum = VECTOR_3["a"][:-1] + "x"
        assert_raises_rpc_error(-5, "Invalid codex32 string at position 1: bad checksum", wallet.addhdkey, codex32=[VECTOR_3["c"], bad_checksum, VECTOR_3["d"]])
        assert_raises_rpc_error(-5, "Invalid codex32 string at position 0: bech32 decode failure", wallet.addhdkey, codex32=["Ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"])
        address = self.nodes[0].get_wallet_rpc(self.default_wallet_name).getnewaddress()
        assert_raises_rpc_error(-5, "Invalid codex32 string at position 0: hrp differed from 'ms'", wallet.addhdkey, codex32=[address])
        # BIP 93 only encodes 16, 20, 24, 28, 32 and 64 byte master seeds
        assert_raises_rpc_error(-5, "Invalid codex32 string at position 0: invalid length", wallet.addhdkey, codex32=["ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea"])
        assert_raises_rpc_error(-5, "Invalid codex32 string at position 0: invalid share index", wallet.addhdkey, codex32=["ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p"])

        self.log.info("Reject sets of codex32 strings that do not recover a secret")
        assert_raises_rpc_error(-8, "codex32 needs a codex32 secret or its shares", wallet.addhdkey, codex32=[])
        assert_raises_rpc_error(-8, "Recovering this codex32 secret takes exactly 3 shares, got 1", wallet.addhdkey, codex32=[VECTOR_3["a"]])
        assert_raises_rpc_error(-8, "Recovering this codex32 secret takes exactly 3 shares, got 2", wallet.addhdkey, codex32=[VECTOR_3["a"], VECTOR_3["c"]])
        assert_raises_rpc_error(-8, "Recovering this codex32 secret takes exactly 3 shares, got 4", wallet.addhdkey, codex32=[VECTOR_3["a"], VECTOR_3["c"], VECTOR_3["d"], VECTOR_3["e"]])
        assert_raises_rpc_error(-5, "Could not recover codex32 secret: tried to derive a share but two input shares had the same index", wallet.addhdkey, codex32=[VECTOR_3["a"], VECTOR_3["a"], VECTOR_3["c"]])
        assert_raises_rpc_error(-5, "Could not recover codex32 secret: tried to derive a share but input shares had inconsistent seed IDs", wallet.addhdkey, codex32=[VECTOR_2["a"], VECTOR_3["a"]])
        assert_raises_rpc_error(-5, "Could not recover codex32 secret: tried to derive a share but input shares had inconsistent seed IDs", wallet.addhdkey, codex32=[VECTOR_3["a"], VECTOR_2["a"]])
        assert_raises_rpc_error(-8, "A codex32 secret (share index s) must be given on its own", wallet.addhdkey, codex32=[VECTOR_3["secret"], VECTOR_3["a"], VECTOR_3["c"]])
        assert_raises_rpc_error(-8, "A codex32 secret (share index s) must be given on its own", wallet.addhdkey, codex32=[VECTOR_1["secret"], VECTOR_1["secret"]])

        self.log.info("Reject hdkey together with codex32")
        tprv = master_xprv(VECTOR_1["seed"], TPRV_VERSION)
        assert_raises_rpc_error(-8, "Cannot use both hdkey and codex32", wallet.addhdkey, hdkey=tprv, codex32=[VECTOR_1["secret"]])

        # Nothing was added by the failed calls
        assert_equal(wallet.gethdkeys(), [])

    def test_wallet_state(self):
        self.log.info("Reject codex32 in wallets that cannot take the key")
        watch_only = self.blank_wallet(disable_private_keys=True)
        assert_raises_rpc_error(-4, "addhdkey is not available for wallets without private keys", watch_only.addhdkey, codex32=[VECTOR_1["secret"]])

        encrypted = self.blank_wallet(passphrase="pass")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first.", encrypted.addhdkey, codex32=[VECTOR_1["secret"]])
        with WalletUnlock(encrypted, "pass"):
            assert_equal(encrypted.addhdkey(codex32=[VECTOR_1["secret"]])["xpub"], self.expected_xpub(VECTOR_1["seed"]))

        self.log.info("Reject a codex32 secret whose HD key is already in the wallet")
        wallet = self.blank_wallet()
        wallet.addhdkey(codex32=[VECTOR_2["a"], VECTOR_2["c"]])
        assert_raises_rpc_error(-4, "HD key already exists", wallet.addhdkey, codex32=[VECTOR_2["secret"]])
        assert_raises_rpc_error(-4, "HD key already exists", wallet.addhdkey, hdkey=master_xprv(VECTOR_2["seed"], TPRV_VERSION))


if __name__ == '__main__':
    WalletCodex32Test(__file__).main()
