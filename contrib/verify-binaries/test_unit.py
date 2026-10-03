#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Unit tests for the signature threshold in verify.py. Run without network."""

import argparse
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "verify_binaries", Path(__file__).with_name("verify.py")
)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def make_signature(fingerprint, trusted=False, key=None):
    signature = VERIFY.SigData()
    signature.key = key or fingerprint[-16:]
    signature.fingerprint = fingerprint
    signature.name = fingerprint
    signature.trusted = trusted
    return signature


class VerifyBinariesTest(unittest.TestCase):
    def verify_signatures(self, signatures, trusted_keys="", threshold=3):
        args = argparse.Namespace(
            import_keys=False,
            keyserver="unused",
            min_good_sigs=threshold,
            trusted_keys=trusted_keys,
            verbose=False,
        )
        with patch.object(
            VERIFY,
            "check_multisig",
            return_value=(2, "", signatures, [], []),
        ):
            return VERIFY.verify_shasums_signature("signatures", "sums", args)[0]

    def test_parse_primary_fingerprint(self):
        signing_fingerprint = "0" * 40
        primary_fingerprint = "1" * 40
        output = [
            "[GNUPG:] NEWSIG",
            "[GNUPG:] GOODSIG 0000000000000000 Signer",
            f"[GNUPG:] VALIDSIG {signing_fingerprint} 2026-01-01 0 0 4 0 1 10 00 {primary_fingerprint}",
        ]
        good, unknown, bad = VERIFY.parse_gpg_result(output)
        self.assertEqual(good[0].fingerprint, primary_fingerprint)
        self.assertEqual(unknown, [])
        self.assertEqual(bad, [])

    def test_keyring_signers_meet_threshold_by_default(self):
        signatures = [make_signature(str(i) * 40) for i in range(1, 4)]
        result = self.verify_signatures(signatures)
        self.assertEqual(result, VERIFY.ReturnCode.SUCCESS)

    def test_duplicate_keyring_signer_does_not_meet_threshold(self):
        fingerprint = "1" * 40
        signatures = [
            make_signature(fingerprint, key=str(i) * 16) for i in range(1, 4)
        ]
        result = self.verify_signatures(signatures)
        self.assertEqual(result, VERIFY.ReturnCode.NOT_ENOUGH_GOOD_SIGS)

    def test_unlisted_signatures_do_not_meet_threshold(self):
        signatures = [make_signature(str(i) * 40) for i in range(1, 4)]
        result = self.verify_signatures(signatures, trusted_keys="4" * 40)
        self.assertEqual(result, VERIFY.ReturnCode.NOT_ENOUGH_GOOD_SIGS)

    def test_signature_without_fingerprint_does_not_meet_threshold(self):
        signature = make_signature("1" * 40, trusted=True)
        signature.fingerprint = None
        result = self.verify_signatures([signature], threshold=1)
        self.assertEqual(result, VERIFY.ReturnCode.NOT_ENOUGH_GOOD_SIGS)

    def test_unlisted_signatures_do_not_supplement_listed_signatures(self):
        signatures = [make_signature(str(i) * 40) for i in range(1, 4)]
        result = self.verify_signatures(signatures, trusted_keys="1" * 40)
        self.assertEqual(result, VERIFY.ReturnCode.NOT_ENOUGH_GOOD_SIGS)

    def test_duplicate_signer_does_not_meet_threshold(self):
        fingerprint = "1" * 40
        signatures = [
            make_signature(fingerprint, key=str(i) * 16) for i in range(1, 4)
        ]
        result = self.verify_signatures(signatures, trusted_keys=fingerprint)
        self.assertEqual(result, VERIFY.ReturnCode.NOT_ENOUGH_GOOD_SIGS)

    def test_distinct_trusted_signers_meet_threshold(self):
        fingerprints = [str(i) * 40 for i in range(1, 4)]
        signatures = [make_signature(fingerprint) for fingerprint in fingerprints]
        result = self.verify_signatures(signatures, trusted_keys=",".join(fingerprints))
        self.assertEqual(result, VERIFY.ReturnCode.SUCCESS)

    def test_distinct_gpg_trusted_signers_meet_threshold(self):
        signatures = [
            make_signature(str(i) * 40, trusted=True) for i in range(1, 4)
        ]
        result = self.verify_signatures(signatures)
        self.assertEqual(result, VERIFY.ReturnCode.SUCCESS)

    def test_parse_trusted_keys(self):
        self.assertEqual(
            VERIFY.parse_trusted_keys(" " + "a" * 40 + ", ,AAAA " + "a" * 36),
            {"A" * 40},
        )
        self.assertEqual(VERIFY.parse_trusted_keys(""), set())
        with self.assertRaises(ValueError):
            VERIFY.parse_trusted_keys("A" * 16)

    def test_fingerprint_is_not_added_to_json_representation(self):
        signature = make_signature("1" * 40)
        self.assertNotIn("fingerprint", repr(signature))


if __name__ == "__main__":
    unittest.main()
