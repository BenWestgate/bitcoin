// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/strencodings.h>
#include <wallet/codex32.h>

#include <cassert>
#include <string>
#include <vector>

namespace wallet {
namespace {

FUZZ_TARGET(codex32)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    std::vector<codex32::Result> valid;
    LIMITED_WHILE(fdp.remaining_bytes(), 10) {
        if (fdp.ConsumeBool()) {
            // Decode an arbitrary string. A valid one re-encodes to itself.
            const std::string str{fdp.ConsumeRandomLengthString(128)};
            codex32::Result res{str};
            if (res.IsValid()) {
                assert(CaseInsensitiveEqual(str, res.Encode()));
                valid.push_back(std::move(res));
            }
        } else {
            // Construct a string from its parts. A valid one decodes to the same parts.
            const size_t k{fdp.ConsumeIntegralInRange<size_t>(0, 10)};
            const std::string id{fdp.ConsumeRandomLengthString(5)};
            const char share_idx{fdp.ConsumeIntegral<char>()};
            const auto payload{fdp.ConsumeBytes<unsigned char>(fdp.ConsumeIntegralInRange<size_t>(0, 65))};
            codex32::Result res{"ms", k, id, share_idx, payload};
            if (res.IsValid()) {
                const codex32::Result dec{res.Encode()};
                assert(dec.IsValid());
                assert(dec.GetK() == k);
                assert(dec.GetIdString() == ToLower(id));
                assert(dec.GetShareIndex() == ToLower(share_idx));
                assert(dec.GetPayload() == payload);
                valid.push_back(std::move(res));
            }
        }
    }

    // Interpolate a subset of the valid strings. This never crashes, and a valid
    // result keeps the threshold, identifier and length of its exactly k inputs.
    std::vector<codex32::Result> shares;
    for (const auto& res : valid) {
        if (fdp.ConsumeBool()) shares.push_back(res);
    }
    const codex32::Result out{shares, fdp.ConsumeIntegral<char>()};
    if (out.IsValid()) {
        assert(shares.size() == shares[0].GetK());
        assert(out.GetK() == shares[0].GetK());
        assert(out.GetIdString() == shares[0].GetIdString());
        assert(out.GetPayload().size() == shares[0].GetPayload().size());
        const codex32::Result dec{out.Encode()};
        assert(dec.IsValid());
        assert(dec.GetPayload() == out.GetPayload());
    }
}

} // namespace
} // namespace wallet
