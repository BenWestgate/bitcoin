// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <wallet/codex32.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
/** Return the BIP 32 master xprv for the seed in a codex32 secret. */
std::string MasterXprv(const codex32::Result& secret)
{
    BOOST_REQUIRE(secret.IsValid());
    BOOST_REQUIRE_EQUAL(secret.GetShareIndex(), 's');
    const auto seed{secret.GetPayload()};
    CExtKey master;
    master.SetSeed(std::as_bytes(std::span{seed}));
    return EncodeExtKey(master);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(codex32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(codex32_bip93_misc_invalid)
{
    // This example uses a "0" threshold with a non-"s" index
    const std::string input1 = "ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p";
    const auto dec1 = codex32::Result{input1};
    BOOST_CHECK_EQUAL(dec1.error(), codex32::INVALID_SHARE_IDX);

    // This example has a threshold that is not a digit.
    const std::string input2 = "ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg";
    const auto dec2 = codex32::Result{input2};
    BOOST_CHECK_EQUAL(dec2.error(), codex32::INVALID_K);
}

BOOST_AUTO_TEST_CASE(codex32_bip93_vector_1)
{
    const std::string input = "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw";

    const auto dec = codex32::Result{input};
    BOOST_CHECK(dec.IsValid());
    BOOST_CHECK_EQUAL(dec.error(), codex32::OK);
    BOOST_CHECK_EQUAL(dec.GetHrp(), "ms");
    BOOST_CHECK_EQUAL(dec.GetK(), 0);
    BOOST_CHECK_EQUAL(dec.GetIdString(), "test");
    BOOST_CHECK_EQUAL(dec.GetShareIndex(), 's');

    const auto payload = dec.GetPayload();
    BOOST_CHECK_EQUAL(payload.size(), 16);
    BOOST_CHECK_EQUAL(HexStr(payload), "318c6318c6318c6318c6318c6318c631");

    BOOST_CHECK_EQUAL(MasterXprv(dec), "xprv9s21ZrQH143K3taPNekMd9oV5K6szJ8ND7vVh6fxicRUMDcChr3bFFzuxY8qP3xFFBL6DWc2uEYCfBFZ2nFWbAqKPhtCLRjgv78EZJDEfpL");

    // Try re-encoding
    BOOST_CHECK_EQUAL(input, dec.Encode());

    // Try directly constructing the share
    const auto direct = codex32::Result("ms", 0, "test", 's', payload);
    BOOST_CHECK(direct.IsValid());
    BOOST_CHECK_EQUAL(direct.error(), codex32::OK);
    BOOST_CHECK_EQUAL(direct.GetIdString(), "test");
    BOOST_CHECK_EQUAL(direct.GetShareIndex(), 's');

    // We cannot check that the codex32 string is exactly the same as the
    // input, since it will not be -- the test vector has nonzero trailing
    // bits while our code will always choose zero trailing bits. But we
    // can at least check that the payloads are identical.
    const auto payload_direct = direct.GetPayload();
    BOOST_CHECK_EQUAL(HexStr(payload), HexStr(payload_direct));
}

BOOST_AUTO_TEST_CASE(codex32_bip93_vector_2)
{
    const std::string input_a = "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM";
    const auto dec_a = codex32::Result{input_a};
    BOOST_CHECK(dec_a.IsValid());
    BOOST_CHECK_EQUAL(dec_a.GetHrp(), "ms");
    BOOST_CHECK_EQUAL(dec_a.GetK(), 2);
    BOOST_CHECK_EQUAL(dec_a.GetIdString(), "name");
    BOOST_CHECK_EQUAL(dec_a.GetShareIndex(), 'a');
    BOOST_CHECK(CaseInsensitiveEqual(input_a, dec_a.Encode()));

    const std::string input_c = "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN";
    const auto dec_c = codex32::Result{input_c};
    BOOST_CHECK(dec_c.IsValid());
    BOOST_CHECK_EQUAL(dec_c.GetHrp(), "ms");
    BOOST_CHECK_EQUAL(dec_c.GetK(), 2);
    BOOST_CHECK_EQUAL(dec_c.GetIdString(), "name");
    BOOST_CHECK_EQUAL(dec_c.GetShareIndex(), 'c');
    BOOST_CHECK(CaseInsensitiveEqual(input_c, dec_c.Encode()));

    const auto d = codex32::Result{{input_a, input_c}, 'd'};
    BOOST_CHECK(d.IsValid());
    BOOST_CHECK_EQUAL(d.GetHrp(), "ms");
    BOOST_CHECK_EQUAL(d.GetK(), 2);
    BOOST_CHECK_EQUAL(d.GetIdString(), "name");
    BOOST_CHECK_EQUAL(d.GetShareIndex(), 'd');
    BOOST_CHECK(CaseInsensitiveEqual("MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG", d.Encode()));

    const auto err1 = codex32::Result{{}, 's'};
    BOOST_CHECK_EQUAL(err1.error(), codex32::TOO_FEW_SHARES);
    const auto err2 = codex32::Result{{input_c}, 's'};
    BOOST_CHECK_EQUAL(err2.error(), codex32::TOO_FEW_SHARES);
    const auto err3 = codex32::Result{{input_a, input_c}, 'b'};
    BOOST_CHECK_EQUAL(err3.error(), codex32::INVALID_SHARE_IDX);
    // Recovery takes exactly k shares
    const auto err4 = codex32::Result{{input_a, input_c, d}, 's'};
    BOOST_CHECK_EQUAL(err4.error(), codex32::TOO_MANY_SHARES);

    const auto s = codex32::Result{{input_a, input_c}, 's'};
    BOOST_CHECK(s.IsValid());
    BOOST_CHECK_EQUAL(s.GetHrp(), "ms");
    BOOST_CHECK_EQUAL(s.GetK(), 2);
    BOOST_CHECK_EQUAL(s.GetIdString(), "name");
    BOOST_CHECK_EQUAL(s.GetShareIndex(), 's');
    BOOST_CHECK(CaseInsensitiveEqual("MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW", s.Encode()));

    const auto seed = s.GetPayload();
    BOOST_CHECK_EQUAL(seed.size(), 16);
    BOOST_CHECK_EQUAL(HexStr(seed), "d1808e096b35b209ca12132b264662a5");
    BOOST_CHECK_EQUAL(MasterXprv(s), "xprv9s21ZrQH143K2NkobdHxXeyFDqE44nJYvzLFtsriatJNWMNKznGoGgW5UMTL4fyWtajnMYb5gEc2CgaKhmsKeskoi9eTimpRv2N11THhPTU");

    // Any two of the three shares recover the same secret
    BOOST_CHECK_EQUAL(codex32::Result({input_c, d}, 's').Encode(), s.Encode());
    BOOST_CHECK_EQUAL(codex32::Result({d, input_a}, 's').Encode(), s.Encode());
}

BOOST_AUTO_TEST_CASE(codex32_bip93_vector_3)
{
    const auto s = codex32::Result("ms", 3, "Cash", 's', ParseHex("ffeeddccbbaa99887766554433221100"));
    BOOST_CHECK(s.IsValid());
    BOOST_CHECK_EQUAL(s.GetIdString(), "cash");
    BOOST_CHECK_EQUAL(s.GetShareIndex(), 's');
    BOOST_CHECK_EQUAL(s.GetK(), 3);
    BOOST_CHECK_EQUAL(s.Encode(), "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln");
    BOOST_CHECK_EQUAL(MasterXprv(s), "xprv9s21ZrQH143K266qUcrDyYJrSG7KA3A7sE5UHndYRkFzsPQ6xwUhEGK1rNuyyA57Vkc1Ma6a8boVqcKqGNximmAe9L65WsYNcNitKRPnABd");

    // Any choice of the two padding bits encodes the same master seed
    for (const auto& alt : {
             "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln",
             "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r",
             "ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6",
             "ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2",
         }) {
        const auto s_alt = codex32::Result{alt};
        BOOST_CHECK(s_alt.IsValid());
        BOOST_CHECK_EQUAL(HexStr(s_alt.GetPayload()), "ffeeddccbbaa99887766554433221100");
    }

    const auto a = codex32::Result{"ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t"};
    BOOST_CHECK(a.IsValid());
    BOOST_CHECK_EQUAL(a.GetIdString(), "cash");
    BOOST_CHECK_EQUAL(a.GetShareIndex(), 'a');
    BOOST_CHECK_EQUAL(a.GetK(), 3);

    const auto c = codex32::Result{"ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr"};
    BOOST_CHECK(c.IsValid());
    BOOST_CHECK_EQUAL(c.GetIdString(), "cash");
    BOOST_CHECK_EQUAL(c.GetShareIndex(), 'c');
    BOOST_CHECK_EQUAL(c.GetK(), 3);

    const auto err1 = codex32::Result{{}, 'd'};
    BOOST_CHECK_EQUAL(err1.error(), codex32::TOO_FEW_SHARES);
    const auto err2 = codex32::Result{{a, c}, 'd'};
    BOOST_CHECK_EQUAL(err2.error(), codex32::TOO_FEW_SHARES);
    const auto err3 = codex32::Result{{s, a}, 'd'};
    BOOST_CHECK_EQUAL(err3.error(), codex32::TOO_FEW_SHARES);
    const auto err4 = codex32::Result{{s, s, a}, 'd'};
    BOOST_CHECK_EQUAL(err4.error(), codex32::DUPLICATE_SHARE);

    const auto d = codex32::Result{{s, a, c}, 'd'};
    BOOST_CHECK(d.IsValid());
    BOOST_CHECK_EQUAL(d.GetIdString(), "cash");
    BOOST_CHECK_EQUAL(d.GetShareIndex(), 'd');
    BOOST_CHECK_EQUAL(d.GetK(), 3);
    BOOST_CHECK_EQUAL(d.Encode(), "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm");

    const auto e = codex32::Result{{a, c, d}, 'e'};
    BOOST_CHECK(e.IsValid());
    BOOST_CHECK_EQUAL(e.GetIdString(), "cash");
    BOOST_CHECK_EQUAL(e.GetShareIndex(), 'e');
    BOOST_CHECK_EQUAL(e.GetK(), 3);
    BOOST_CHECK_EQUAL(e.Encode(), "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9");

    const auto f = codex32::Result{{a, s, d}, 'f'};
    BOOST_CHECK(f.IsValid());
    BOOST_CHECK_EQUAL(f.GetIdString(), "cash");
    BOOST_CHECK_EQUAL(f.GetShareIndex(), 'f');
    BOOST_CHECK_EQUAL(f.GetK(), 3);
    BOOST_CHECK_EQUAL(f.Encode(), "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704");

    // Any three of the five shares recover the secret, but four do not
    BOOST_CHECK_EQUAL(codex32::Result({c, e, f}, 's').Encode(), s.Encode());
    BOOST_CHECK_EQUAL(codex32::Result({f, d, a}, 's').Encode(), s.Encode());
    const auto err5 = codex32::Result{{a, c, d, e}, 's'};
    BOOST_CHECK_EQUAL(err5.error(), codex32::TOO_MANY_SHARES);

    // Invalid input shares are reported as such
    const auto err6 = codex32::Result{{a, c, codex32::Result{"ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rn"}}, 's'};
    BOOST_CHECK_EQUAL(err6.error(), codex32::BAD_CHECKSUM);

    // Mismatched data
    const auto g1 = codex32::Result{"ms", 2, "cash", 'g', ParseHex("ffeeddccbbaa99887766554433221100")};
    BOOST_CHECK(g1.IsValid());
    const auto err_s1 = codex32::Result{{a, c, g1}, 's'};
    BOOST_CHECK_EQUAL(err_s1.error(), codex32::MISMATCH_K);
    // Consistency is checked before the number of shares
    const auto err_s1b = codex32::Result{{g1, a, c}, 's'};
    BOOST_CHECK_EQUAL(err_s1b.error(), codex32::MISMATCH_K);

    const auto g2 = codex32::Result{"ms", 3, "leet", 'g', ParseHex("ffeeddccbbaa99887766554433221100")};
    BOOST_CHECK(g2.IsValid());
    const auto err_s2 = codex32::Result{{a, c, g2}, 's'};
    BOOST_CHECK_EQUAL(err_s2.error(), codex32::MISMATCH_ID);

    const auto g3 = codex32::Result{"ms", 3, "cash", 'g', ParseHex("ffeeddccbbaa99887766554433221100aabbccdd")};
    BOOST_CHECK(g3.IsValid());
    const auto err_s3 = codex32::Result{{a, c, g3}, 's'};
    BOOST_CHECK_EQUAL(err_s3.error(), codex32::MISMATCH_LENGTH);
    // The longer share first
    const auto err_s4 = codex32::Result{{g3, a, c}, 's'};
    BOOST_CHECK_EQUAL(err_s4.error(), codex32::MISMATCH_LENGTH);
}

BOOST_AUTO_TEST_CASE(codex32_bip93_vector_4)
{
    const std::string seed = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    const auto s = codex32::Result{"ms", 0, "leet", 's', ParseHex(seed)};
    BOOST_CHECK(s.IsValid());
    BOOST_CHECK_EQUAL(s.GetIdString(), "leet");
    BOOST_CHECK_EQUAL(s.GetShareIndex(), 's');
    BOOST_CHECK_EQUAL(s.GetK(), 0);
    BOOST_CHECK_EQUAL(HexStr(s.GetPayload()), seed);
    BOOST_CHECK_EQUAL(s.Encode(), "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma");
    BOOST_CHECK_EQUAL(MasterXprv(s), "xprv9s21ZrQH143K3s41UCWxXTsU4TRrhkpD1t21QJETan3hjo8DP5LFdFcB5eaFtV8x6Y9aZotQyP8KByUjgLTbXCUjfu2iosTbMv98g8EQoqr");

    // An unshared secret cannot be interpolated
    const auto err1 = codex32::Result{{s}, 's'};
    BOOST_CHECK_EQUAL(err1.error(), codex32::INVALID_K);

    std::vector<std::string> alternates = {
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpj82dp34u6lqtd",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqzsrs4pnh7jmpj5",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqrfcpap2w8dqezy",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqy5tdvphn6znrf0",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqx05xupvgp4v6qx",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq8k0h5p43c2hzsk",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqgum7hplmjtr8ks",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqf9q0lpxzt5clxq",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq28y48pyqfuu7le",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqt7ly0paesr8x0f",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqvrvg7pqydv5uyz",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqd6hekpea5n0y5j",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqwcnrwpmlkmt9dt",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq0pgjxpzx0ysaam",
    };
    for (const auto& alt : alternates) {
        const auto s_alt = codex32::Result{alt};
        BOOST_CHECK(s_alt.IsValid());
        BOOST_CHECK_EQUAL(HexStr(s_alt.GetPayload()), seed);
    }
}

BOOST_AUTO_TEST_CASE(codex32_bip93_vector_5)
{
    const auto s = codex32::Result{"MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK"};
    BOOST_CHECK(s.IsValid());
    BOOST_CHECK_EQUAL(s.error(), codex32::OK);
    BOOST_CHECK_EQUAL(s.GetIdString(), "0c8v");
    BOOST_CHECK_EQUAL(s.GetShareIndex(), 's');
    BOOST_CHECK_EQUAL(s.GetK(), 0);
    BOOST_CHECK_EQUAL(HexStr(s.GetPayload()), "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9");
    BOOST_CHECK_EQUAL(MasterXprv(s), "xprv9s21ZrQH143K4UYT4rP3TZVKKbmRVmfRqTx9mG2xCy2JYipZbkLV8rwvBXsUbEv9KQiUD7oED1Wyi9evZzUn2rqK9skRgPkNaAzyw3YrpJN");
    // This is a long codex32 string, and re-encodes with the long checksum
    BOOST_CHECK(CaseInsensitiveEqual(s.Encode(), "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK"));
}

BOOST_AUTO_TEST_CASE(codex32_bip93_vectors_6_7_8)
{
    const std::array<std::pair<std::string, std::string>, 3> vectors{{
        {"ms10seedsqqqsyqcyq5rqwzqfpg9scrgwpugpzysn9vaqzzvs20xnl", "000102030405060708090a0b0c0d0e0f10111213"},
        {"ms10seedsyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdau84gz0632s0xs", "202122232425262728292a2b2c2d2e2f3031323334353637"},
        {"ms10seedsgpq5ys6yg4rywjzfff95cn2wfag9z5jn2324v46ct9d9hrcduqw8c3lccl", "404142434445464748494a4b4c4d4e4f505152535455565758595a5b"},
    }};
    for (const auto& [str, seed] : vectors) {
        const auto s = codex32::Result{str};
        BOOST_CHECK(s.IsValid());
        BOOST_CHECK_EQUAL(s.GetIdString(), "seed");
        BOOST_CHECK_EQUAL(s.GetShareIndex(), 's');
        BOOST_CHECK_EQUAL(s.GetK(), 0);
        BOOST_CHECK_EQUAL(HexStr(s.GetPayload()), seed);

        // The same seed constructed directly uses the same length and checksum
        const auto direct = codex32::Result{"ms", 0, "seed", 's', ParseHex(seed)};
        BOOST_CHECK(direct.IsValid());
        BOOST_CHECK_EQUAL(direct.Encode().size(), str.size());
        BOOST_CHECK_EQUAL(HexStr(codex32::Result{direct.Encode()}.GetPayload()), seed);
    }
}

BOOST_AUTO_TEST_CASE(codex32_errors)
{
    const std::vector<codex32::Result> errs = {
        codex32::Result("ms", 3, "cash", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        // bad hrp
        codex32::Result("bc", 3, "cash", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        // bad ID len
        codex32::Result("ms", 3, "cas", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 3, "cashcashcash", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 3, "", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        // bad id char
        codex32::Result("ms", 3, "bash", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        // bad k
        codex32::Result("ms", 1, "cash", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 10, "cash", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 100000, "cash", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        // bad share idx
        codex32::Result("ms", 100000, "cash", 'b', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 100000, "cash", 'i', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 100000, "cash", '1', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 100000, "cash", 'o', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 100000, "cash", ' ', ParseHex("ffeeddccbbaa99887766554433221100")),
        // bad payload length (BIP 93 only encodes 16, 20, 24, 28, 32 and 64 byte seeds)
        codex32::Result("ms", 3, "cash", 's', ParseHex("ffeeddccbbaa99887766554433221100ab")),
        codex32::Result("ms", 3, "cash", 's', ParseHex("ffeeddccbbaa998877665544332211")),
        codex32::Result("ms", 3, "cash", 's', {}),
        // non-ASCII characters
        codex32::Result("ms", 3, "cas\xe9", 's', ParseHex("ffeeddccbbaa99887766554433221100")),
        codex32::Result("ms", 3, "cash", '\xe9', ParseHex("ffeeddccbbaa99887766554433221100")),
    };

    BOOST_CHECK_EQUAL(errs[0].error(), codex32::OK);
    BOOST_CHECK_EQUAL(errs[1].error(), codex32::INVALID_HRP);
    BOOST_CHECK_EQUAL(errs[2].error(), codex32::INVALID_ID_LEN);
    BOOST_CHECK_EQUAL(errs[3].error(), codex32::INVALID_ID_LEN);
    BOOST_CHECK_EQUAL(errs[4].error(), codex32::INVALID_ID_LEN);
    BOOST_CHECK_EQUAL(errs[5].error(), codex32::INVALID_ID_CHAR);
    BOOST_CHECK_EQUAL(errs[6].error(), codex32::INVALID_K);
    BOOST_CHECK_EQUAL(errs[7].error(), codex32::INVALID_K);
    BOOST_CHECK_EQUAL(errs[8].error(), codex32::INVALID_K);
    BOOST_CHECK_EQUAL(errs[9].error(), codex32::INVALID_SHARE_IDX);
    BOOST_CHECK_EQUAL(errs[10].error(), codex32::INVALID_SHARE_IDX);
    BOOST_CHECK_EQUAL(errs[11].error(), codex32::INVALID_SHARE_IDX);
    BOOST_CHECK_EQUAL(errs[12].error(), codex32::INVALID_SHARE_IDX);
    BOOST_CHECK_EQUAL(errs[13].error(), codex32::INVALID_SHARE_IDX);
    BOOST_CHECK_EQUAL(errs[14].error(), codex32::INVALID_LENGTH);
    BOOST_CHECK_EQUAL(errs[15].error(), codex32::INVALID_LENGTH);
    BOOST_CHECK_EQUAL(errs[16].error(), codex32::INVALID_LENGTH);
    BOOST_CHECK_EQUAL(errs[17].error(), codex32::INVALID_ID_CHAR);
    BOOST_CHECK_EQUAL(errs[18].error(), codex32::INVALID_SHARE_IDX);
}

BOOST_AUTO_TEST_CASE(codex32_bip93_invalid_1)
{
    std::vector<std::string> bad_checksum = {
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghp",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxlk3yepcstwr",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx6pgnv7jnpcsp",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxx0cpvr7n4geq",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxm5252y7d3lr",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxrd9sukzl05ej",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxc55srw5jrm0",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxgc7rwhtudwc",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx4gy22afwghvs",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pe0",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pew",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqyadsp3nywm8a",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzvg7ar4hgaejk",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcznau0advgxqe",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxch3jrc6j5040j",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx52gxl6ppv40mcv",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7g4g2nhhle8fk",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx63m45uj8ss4x8",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy4r708q7kg65x",
    };
    for (const auto& bad : bad_checksum) {
        auto res = codex32::Result{bad};
        BOOST_CHECK_EQUAL(res.error(), codex32::BAD_CHECKSUM);
    }
}

BOOST_AUTO_TEST_CASE(codex32_bip93_invalid_2)
{
    // These use the wrong checksum for their given data sizes
    std::vector<std::string> bad_checksum = {
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxurfvwmdcmymdufv",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcwm4re8fs78vn",
    };
    for (const auto& bad : bad_checksum) {
        auto res = codex32::Result{bad};
        BOOST_CHECK_EQUAL(res.error(), codex32::BAD_CHECKSUM);
    }
}

BOOST_AUTO_TEST_CASE(codex32_bip93_invalid_3)
{
    // These have improper lengths
    std::vector<std::string> bad_length = {
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxwqey9rfs6smenxa",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxw0a4c70rfefn4",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx9lrwar5zwng4w",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxr335l5tv88js3",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvu7q9nz8p7dj68v",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpq6k542scdxndq3",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxkmfw6jm270mz6ej",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxzhddxw99w7xws",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx42cux6um92rz",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxarja5kqukdhy9",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxky0ua3ha84qk8",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9eheesxadh2n2n9",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9llwmgesfulcj2z",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ev7caq6n9fgkf",
    };
    for (const auto& bad : bad_length) {
        auto res = codex32::Result{bad};
        BOOST_CHECK_EQUAL(res.error(), codex32::INVALID_LENGTH);
    }
}

BOOST_AUTO_TEST_CASE(codex32_bip93_invalid_hrp)
{
    std::vector<std::string> bad_checksum = {
        "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
        "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
        "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxx8t28z74x8hs4l",
        "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxh9d0fhnvfyx3x",
    };
    for (const auto& bad : bad_checksum) {
        auto res = codex32::Result{bad};
        BOOST_CHECK(res.error() == codex32::INVALID_HRP || res.error() == codex32::BECH32_DECODE);
    }
}

BOOST_AUTO_TEST_CASE(codex32_bip93_invalid_case)
{
    std::vector<std::string> bad_checksum = {
        "Ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "mS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "MS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10FAUXsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10fauxSxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10fauxsXXXXXXXXXXXXXXXXXXXXXXXXXXuqxkk05lyf3x2",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxUQXKK05LYF3X2",
    };
    for (const auto& bad : bad_checksum) {
        auto res = codex32::Result{bad};
        BOOST_CHECK_EQUAL(res.error(), codex32::BECH32_DECODE);
    }
}

BOOST_AUTO_TEST_SUITE_END()
