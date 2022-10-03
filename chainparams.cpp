// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>
#include <assert.h>
#include <chainparamsseeds.h>

/*
./genesis 
Usage: ./genesis [options] <pubkey> "<timestamp>" <nBits> <startNonce> <unixtime>
./genesis 04b42165d08e119d9cab326b1b13ec8a41b583dff957d965f92c1bd6d45370f3b229272097795e844a222f35fc9b6dfea88e9f214d72d5475ea5b2b77c5fb4df01 "NY Times 2019/04/06 A Mysterious Infection, Spanning the Globe in a Climate of Secrecy" 486604799
nBits: 0x1d00ffff
startNonce: 0
unixtime: 0

Coinbase: 04ffff001d01044c564e592054696d657320323031392f30342f30362041204d7973746572696f757320496e66656374696f6e2c205370616e6e696e672074686520476c6f626520696e206120436c696d617465206f662053656372656379

PubkeyScript: 4104b42165d08e119d9cab326b1b13ec8a41b583dff957d965f92c1bd6d45370f3b229272097795e844a222f35fc9b6dfea88e9f214d72d5475ea5b2b77c5fb4df01ac

Merkle Hash: 8615558746a24e1748a36df74948579f6372b265caa1e89ba7b07daa754a601f
Byteswapped: 1f604a75aa7db0a79be8a1ca65b272639f574849f76da348174ea24687551586
Generating block...
841154 Hashes/s, Nonce 3865523310
Block found!
Hash: 00000000ae01abf3103b0b0aabfb9b6dc5b60301afdf6dc5aaf99367a0bf2944
Nonce: 3866066997
Unix time: 1664747242
*/

#define CustomParam_nSubsidyHalvingInterval (20) /*default 50050*/
#define CustomParam_nPowTargetTimespan (5 * 60) /*5 * 60 default 14 * 24 * 60 * 60 // two weeks*/
#define CustomParam_nPowTargetSpacing (60) /*60 default 10 * 60*/
#define CustomParam_nMinerConfirmationWindow (CustomParam_nPowTargetTimespan / CustomParam_nPowTargetSpacing) /*2016 // nPowTargetTimespan / nPowTargetSpacing*/
#define CustomParam_nRuleChangeActivationThreshold (CustomParam_nMinerConfirmationWindow * 0.95) /*1916 // 95% of 2016*/
// testnet
#define CustomParam_TestNetnSubsidyHalvingInterval (20) /*default 50050*/
#define CustomParam_TestNetnPowTargetTimespan (5 * 60) /*5 * 60 default 14 * 24 * 60 * 60 // two weeks*/
#define CustomParam_TestNetnPowTargetSpacing (60) /*60 default 10 * 60*/
#define CustomParam_TestNetnMinerConfirmationWindow (CustomParam_TestNetnPowTargetTimespan / CustomParam_TestNetnPowTargetSpacing) /*2016 // nPowTargetTimespan / nPowTargetSpacing*/
#define CustomParam_TestNetnRuleChangeActivationThreshold (CustomParam_TestNetnMinerConfirmationWindow * 0.75) /*1512 // 75% for testchains*/
// regtest
#define CustomParam_RegTestnSubsidyHalvingInterval (20) /*default 150*/
#define CustomParam_RegTestnPowTargetTimespan (5 * 60) /*default 14 * 24 * 60 * 60 // two weeks*/
#define CustomParam_RegTestnPowTargetSpacing  (60) /*60 default 10 * 60*/
#define CustomParam_RegTestnMinerConfirmationWindow (144 * 0.75) /*default 108 // 75% for testchains*/
#define CustomParam_RegTestnRuleChangeActivationThreshold (144) /*default 144 // Faster than normal for regtest (144 instead of 2016)*/
// general genesis params
#define CustomParam_nBits 0x1d00ffff // 486604799
#define CustomParam_nNonce 3866066997
#define CustomParam_nTime  1664747242
#define CustomParam_GenesisParamsTestNetParams \
        CustomParam_nTime   , CustomParam_nNonce, CustomParam_nBits,        1, 1000000 * COIN
        /* 1544904235       , 0x00000006        , 545259519        ,        1, 1000000 * COIN */
        /*    nTime         , nNonce            , nBits            , nVersion, genesisReward  */
#define CustomParam_GenesisParamsRegTest \
        CustomParam_nTime   , CustomParam_nNonce, CustomParam_nBits,        1, 1000000 * COIN
        /* 1544904235       , 0x00000006        , 545259519        ,        1, 1000000 * COIN */
        /*    nTime         , nNonce            , nBits            , nVersion, genesisReward   */
#define CustomParam_GenesisParamsCMain      \
        CustomParam_nTime   , CustomParam_nNonce, CustomParam_nBits,        1, 1000000 * COIN
        /* 1544904235,      ,  0x00000006       , 545259519        ,        1, 1000000 * COIN  */
        /*    nTime         ,  nNonce           , nBits            , nVersion, genesisReward   */
#define CustomParam_GenesisBlockHash  "0x00000000ae01abf3103b0b0aabfb9b6dc5b60301afdf6dc5aaf99367a0bf2944" 
#define CustomParam_GenesisMerkleRoot "0x8615558746a24e1748a36df74948579f6372b265caa1e89ba7b07daa754a601f"
#define CustomParam_GenesisPublicKey  "04b42165d08e119d9cab326b1b13ec8a41b583dff957d965f92c1bd6d45370f3b229272097795e844a222f35fc9b6dfea88e9f214d72d5475ea5b2b77c5fb4df01"
// #define CustomParam_GenesisPublicKey  "4104b42165d08e119d9cab326b1b13ec8a41b583dff957d965f92c1bd6d45370f3b229272097795e844a222f35fc9b6dfea88e9f214d72d5475ea5b2b77c5fb4df01ac" pubkeyscript
#define CustomParam_GenesisMiningPhrase "NY Times 2019/04/06 A Mysterious Infection, Spanning the Globe in a Climate of Secrecy"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << CustomParam_nBits << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)); /*default 545259519*/ 
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = CustomParam_GenesisMiningPhrase; /*default "12-13-18 LinkedIn: 'Blockchain developer' is the fastest-growing U.S. job"*/
    const CScript genesisOutputScript = CScript() << ParseHex(CustomParam_GenesisPublicKey) << OP_CHECKSIG; /*default 048f74dca316b3faa7e947919babe20e274d5c1f4cf3366652bd360bb51322f652b575fd0461fb982fd9aabf39c879db9f08a5f505bb5671083bc085c1802eac56*/
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = CustomParam_nSubsidyHalvingInterval; /*default 50050*/
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = CustomParam_nPowTargetTimespan; /*default 14 * 24 * 60 * 60 // two weeks*/
        consensus.nPowTargetSpacing = CustomParam_nPowTargetSpacing; /*default 10 * 60*/
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = CustomParam_nRuleChangeActivationThreshold; /*1916 // 95% of 2016*/
        consensus.nMinerConfirmationWindow = CustomParam_nMinerConfirmationWindow; /*2016 // nPowTargetTimespan / nPowTargetSpacing*/
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = consensus.powLimit;

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256();

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xd3;
        pchMessageStart[1] = 0xf3;
        pchMessageStart[2] = 0xfd;
        pchMessageStart[3] = 0x87;
        nDefaultPort = 8433;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(CustomParam_GenesisParamsCMain);
        consensus.hashGenesisBlock = genesis.GetHash();
        std::cout << consensus.hashGenesisBlock.ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S(CustomParam_GenesisBlockHash)); /*default "0x1918500b88eb211c30bf3ae7a5faa51305bace111344ab696efbd619fe99eb38"*/
        assert(genesis.hashMerkleRoot == uint256S(CustomParam_GenesisMerkleRoot)); /*default "0x634c2897ab0decc26fce8dbedbdb5defd62837948de775499394cb862e91ec95"*/

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // vSeeds.emplace_back("seed.learncoin.sipa.be"); // Pieter Wuille, only supports x1, x5, x9, and xd

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); /*default 1,45 // K */
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); /*default 1,48 // L*/
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239); /*defautl 1,128*/
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF}; /*default 0x04, 0x88, 0xB2, 0x1E*/
        base58Prefixes[EXT_SECRET_KEY] = {0X04, 0x35, 0x83, 0x94}; /*default 0x04, 0x88, 0xAD, 0xE4*/

        bech32_hrp = "lc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000000002e63058c023a9a1de233554f28c7b21380b6c9003f36a8
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = CustomParam_TestNetnSubsidyHalvingInterval; /*default 50050*/
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = CustomParam_TestNetnPowTargetTimespan; 
        consensus.nPowTargetSpacing = CustomParam_TestNetnPowTargetSpacing; 
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = CustomParam_TestNetnRuleChangeActivationThreshold; /*1512 // 75% for testchains*/
        consensus.nMinerConfirmationWindow = CustomParam_TestNetnMinerConfirmationWindow; /*2016 // nPowTargetTimespan / nPowTargetSpacing*/
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = consensus.powLimit;

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256();

        pchMessageStart[0] = 0x9a;
        pchMessageStart[1] = 0xb4;
        pchMessageStart[2] = 0xee;
        pchMessageStart[3] = 0xa9;
        nDefaultPort = 18433;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            CustomParam_GenesisParamsTestNetParams
        );
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S(CustomParam_GenesisBlockHash)); /*default "0x1918500b88eb211c30bf3ae7a5faa51305bace111344ab696efbd619fe99eb38"*/
        assert(genesis.hashMerkleRoot == uint256S(CustomParam_GenesisMerkleRoot)); /*default "0x634c2897ab0decc26fce8dbedbdb5defd62837948de775499394cb862e91ec95"*/

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,107); // k
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,127); // t
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tl";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = CustomParam_RegTestnSubsidyHalvingInterval; /*default 150*/
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = CustomParam_RegTestnPowTargetTimespan; /*default 14 * 24 * 60 * 60 // two weeks*/
        consensus.nPowTargetSpacing = CustomParam_RegTestnPowTargetSpacing; /*default 10 * 60*/
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = CustomParam_RegTestnRuleChangeActivationThreshold; /*default 108 // 75% for testchains*/
        consensus.nMinerConfirmationWindow = CustomParam_RegTestnMinerConfirmationWindow; /*default 144 // Faster than normal for regtest (144 instead of 2016)*/
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xec;
        pchMessageStart[3] = 0x82;
        nDefaultPort = 18544;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(CustomParam_GenesisParamsRegTest);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S(CustomParam_GenesisBlockHash)); /*default "0x1918500b88eb211c30bf3ae7a5faa51305bace111344ab696efbd619fe99eb38"*/
        assert(genesis.hashMerkleRoot == uint256S(CustomParam_GenesisMerkleRoot)); /*default "0x634c2897ab0decc26fce8dbedbdb5defd62837948de775499394cb862e91ec95"*/

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,107); // k
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,127); // t
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "lcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
