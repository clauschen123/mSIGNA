#include "poc.h"
#include <CoinQ/CoinQ_blocks.h>
#include <CoinCore/shabal256.h>
#include <CoinCore/arith_uint256.h>
#include <logger/logger.h>
#include <iostream>
using namespace std;

namespace poc {
    static const int HASH_SIZE = 32;
    static const int HASHES_PER_SCOOP = 2;
    static const int SCOOP_SIZE = HASHES_PER_SCOOP * HASH_SIZE;
    static const int SCOOPS_PER_PLOT = 4096; // original 1MB/plot = 16384
    static const int PLOT_SIZE = SCOOPS_PER_PLOT * SCOOP_SIZE;
    static const int HASH_CAP = 4096;

    /** Burst initial base target */
    static const uint64_t INITIAL_BASE_TARGET = 18325193796L;
    /** Burst max target */
    static const uint64_t MAX_BASE_TARGET = 18325193796L;

    uint64_t CalculateBaseTarget(const ChainHeader& prev, const Coin::CoinBlockHeader &block, FGetPrevBlock getPrevBlock)
    {
        assert(prev.height + 1 >= BCO_FORK_BLOCK_HEIGHT);
        int nPocGenesisBlockHeight = BCO_FORK_BLOCK_HEIGHT + BCOInitBlockCount;
        int nHeight = prev.height + 1;
        if (nHeight <= nPocGenesisBlockHeight) {
            // genesis block & god mode block
            return INITIAL_BASE_TARGET;
        }
        else if (nHeight < nPocGenesisBlockHeight + 4) {
            // < 4
            return INITIAL_BASE_TARGET;
        }
        else if (nHeight < nPocGenesisBlockHeight + 2700) {
            // < 2700
            // [N-1,N-2,N-3,N-4]
            uint64_t avgBaseTarget = prev.bits();
            const ChainHeader *pLastindex = &prev;
            for (int i = nHeight - 2; i >= nHeight - 4; i--) {
                pLastindex = getPrevBlock(pLastindex->prevBlockHash());
                if (pLastindex == nullptr) {
                    break;
                }
                avgBaseTarget += pLastindex->bits();
            }
            avgBaseTarget /= 4;
            assert(pLastindex != nullptr);

            uint64_t curBaseTarget = avgBaseTarget;
            int64_t diffTime = block.timestamp() - pLastindex->timestamp();

            uint64_t newBaseTarget = (curBaseTarget * diffTime) / (300 * 4); // 5m * 60s * 4blocks
            if (newBaseTarget > MAX_BASE_TARGET) {
                newBaseTarget = MAX_BASE_TARGET;
            }
            if (newBaseTarget < (curBaseTarget * 9 / 10)) {
                newBaseTarget = curBaseTarget * 9 / 10;
            }

            if (newBaseTarget == 0) {
                newBaseTarget = 1;
            }

            if (newBaseTarget > (curBaseTarget * 11 / 10)) {
                newBaseTarget = curBaseTarget * 11 / 10;
            }

            return newBaseTarget;
        }
        else {
            // [N-1,N-2,N-3,...,N-25]
            uint64_t avgBaseTarget = prev.bits();
            const ChainHeader *pLastindex = &prev;
            for (int i = nHeight - 2, blockCounter = 1; i >= nHeight - 25; i--, blockCounter++) {
                pLastindex = getPrevBlock(pLastindex->prevBlockHash());
                if (pLastindex == nullptr) {
                    break;
                }
                avgBaseTarget = (avgBaseTarget * blockCounter + pLastindex->bits()) / (blockCounter + 1);
            }
            assert(pLastindex != nullptr);

            int64_t diffTime = block.timestamp() - pLastindex->timestamp();
            int64_t targetTimespan = 5 * 60 * 24; // 5m * 60s * 24blocks

            if (diffTime < targetTimespan / 2) {
                diffTime = targetTimespan / 2;
            }

            if (diffTime > targetTimespan * 2) {
                diffTime = targetTimespan * 2;
            }

            uint64_t curBaseTarget = prev.bits();
            uint64_t newBaseTarget = avgBaseTarget * diffTime / targetTimespan;

            if (newBaseTarget > MAX_BASE_TARGET) {
                newBaseTarget = MAX_BASE_TARGET;
            }

            if (newBaseTarget == 0) {
                newBaseTarget = 1;
            }

            if (newBaseTarget < curBaseTarget * 8 / 10) {
                newBaseTarget = curBaseTarget * 8 / 10;
            }

            if (newBaseTarget > curBaseTarget * 12 / 10) {
                newBaseTarget = curBaseTarget * 12 / 10;
            }

            return newBaseTarget;
        }
    }
    
    uint32_t GetBlockScoopNum(const btc_uint256 &genSig, int nHeight)
    {
        return UintToArith256(shabal256(genSig, htobe64(nHeight))) % 4096;
    }

    btc_uint256 GetBlockGenerationSignature(const Coin::CoinBlockHeader &prevBlock)
    {
        // 使用hashMerkleRoot和nPlotSeed做签名
        btc_uint256 result;

        Coin::plotseed_t plotseed = prevBlock.plotseed();
        uchar_vector merkleRoot = prevBlock.merkleRoot();

        merkleRoot.reverse();

        CShabal256()
            .Write((const unsigned char*)merkleRoot.data(), merkleRoot.size())
            .Write((const unsigned char*)&plotseed, sizeof(plotseed))
            .Finalize((unsigned char*)result.begin());
        return result;
    }

    btc_uint256 shabal256(const btc_uint256 &genSig, int64_t nMix64)
    {
        btc_uint256 result;
        CShabal256()
            .Write((const unsigned char*)genSig.begin(), genSig.size())
            .Write((const unsigned char*)&nMix64, sizeof(nMix64))
            .Finalize((unsigned char*)result.begin());
        return result;
    }

    uint64_t CalculateDeadline(const ChainHeader &prev, const Coin::CoinBlockHeader &block)
    {
        if (prev.height + 1 <= BCO_FORK_BLOCK_HEIGHT + BCOInitBlockCount) {
            // genesis block & god mode block
            return 0;
        }

        btc_uint256 genSig = poc::GetBlockGenerationSignature(prev);
        const uint32_t scopeNum = poc::GetBlockScoopNum(genSig, prev.height + 1);
        const uint64_t addr = htobe64( block.plotseed());
        const uint64_t nonce = htobe64(block.nonce());
        
//         if (prev.height == 502706) {
//             LOGGER(trace) << "\n   genSig:" << genSig.GetHex() ;
//             LOGGER(trace) << "\n   scopeNum:" << scopeNum ;
//             LOGGER(trace) << "\n   addr:" << addr ;
//             LOGGER(trace) << "\n   nonce:" << nonce ;
//         }

        std::unique_ptr<uint8_t> _gendata(new uint8_t[PLOT_SIZE + 16]);
        uint8_t *const gendata = _gendata.get();
        memcpy(gendata + PLOT_SIZE, (const unsigned char*)&addr, 8);
        memcpy(gendata + PLOT_SIZE + 8, (const unsigned char*)&nonce, 8);
        for (int i = PLOT_SIZE; i > 0; i -= HASH_SIZE) {
            int len = PLOT_SIZE + 16 - i;
            if (len > HASH_CAP) {
                len = HASH_CAP;
            }

            btc_uint256 temp;
            CShabal256()
                .Write((const unsigned char*)gendata + i, len)
                .Finalize((unsigned char*)temp.begin());

//             if (prev.height == 502706 && i== PLOT_SIZE) {
//                 LOGGER(trace) << "\n   for i=" << i << "  temp:" << temp.GetHex() ;
//             }

            memcpy((uint8_t*)gendata + i - HASH_SIZE, (const uint8_t*)temp.begin(), HASH_SIZE);
        }
        btc_uint256 base;
        CShabal256()
            .Write((const unsigned char*)gendata, PLOT_SIZE + 16)
            .Finalize((unsigned char*)base.begin());
//         if (prev.height == 502706) {
//             LOGGER(trace) << "\n   base:" << base.GetHex() ;
//         }

        uint8_t data[PLOT_SIZE];
        for (int i = 0; i < PLOT_SIZE; i++) {
            data[i] = (uint8_t)(gendata[i] ^ (base.begin()[i % HASH_SIZE]));
        }
        _gendata.reset(nullptr);

        CShabal256()
            .Write((const unsigned char*)genSig.begin(), genSig.size())
            .Write((const unsigned char*)data + scopeNum * SCOOP_SIZE, SCOOP_SIZE)
            .Finalize((unsigned char*)base.begin());

//         if (prev.height == 502706) {
//             LOGGER(trace) << "\n   base:" << base.GetHex() << ", prev bits:" << prev.bits() ;
//             LOGGER(trace) << "\n   result:" << base.GetUint64(0) / prev.bits();
//         }

        return base.GetUint64(0) / prev.bits();
    }

    bool VerifyGenerationSignature(const ChainHeader& prev, const Coin::CoinBlockHeader& block, FGetPrevBlock getPrevBlock)
    {
        if (block.timestamp() < BCO_BLOCK_UNIXTIME_MIN ||
            block.bits() != CalculateBaseTarget(prev, block, getPrevBlock)) {
            return false;
        }

        if (prev.height + 1 < BCO_FORK_BLOCK_HEIGHT + BCOInitBlockCount) {
            // God Mode
            return true;
        }

        uint64_t deadline = CalculateDeadline(prev, block);
        return block.timestamp() > prev.timestamp() + deadline;
    }

}