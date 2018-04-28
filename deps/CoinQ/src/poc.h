#pragma once
#include <functional>
#include <CoinCore/CoinNodeData.h>
#include <CoinCore/btc_uint256.h>

class uchar_vector;
class ChainHeader;
class btc_uint256;
// class CoinBlockHeader;
namespace poc {

    typedef std::function<const ChainHeader*(const uchar_vector&)>  FGetPrevBlock;

    uint64_t getCurDeadline();

    uint32_t GetBlockScoopNum(const btc_uint256 &genSig, int nHeight);

    btc_uint256 shabal256(const btc_uint256 &genSig, int64_t nMix64);

    btc_uint256 GetBlockGenerationSignature(const Coin::CoinBlockHeader &prevBlock);

    uint64_t CalculateBaseTarget(const ChainHeader& prev, const Coin::CoinBlockHeader &block, FGetPrevBlock getPrevBlock);

    bool VerifyGenerationSignature(const ChainHeader& prev, const Coin::CoinBlockHeader& block, FGetPrevBlock getPrev);
}