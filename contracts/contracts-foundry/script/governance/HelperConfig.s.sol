// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";

contract HelperConfig is Script {

    struct InitializeParams {
        address admin;
        address configSetter;
        address treasury;
        uint256 proposalPassVetoThreshold;
        uint256 minQuorumThreshold;
        uint256 voteActivationDelay;
        uint256 voteDuration;
        uint256 proposalDuration;
        uint256 maxRPCUrlsPerChain;
        IGovernanceTypes.PCR pcrConfig;
        bytes kmsRootServerPubKey;
        string kmsPath;
    }

    struct TokenNetworkConfig {
        uint256 chainId;
        address tokenAddress;
        string[] rpcUrls;
    }

    struct TokenLockConfig {
        address tokenAddress;
        uint256 lockAmount;
    }

    struct Config {
        InitializeParams initializeParams;
        TokenLockConfig[] tokenLockConfigs;
        TokenNetworkConfig[] governanceNetworkConfigs;
    }

    error UnsupportedChainId(uint256 chainId);

    uint256 constant ARBITRUM_ONE_MAINNET = 42161;
    uint256 constant ARBITRUM_SEPOLIA = 421614;
    uint256 constant ETHEREUM_SEPOLIA = 11155111;

    Config public activeConfig;

    constructor() {
        if(block.chainid == ARBITRUM_ONE_MAINNET) {
            activeConfig = getArbitrumOneMainnetConfig();
        } else if (block.chainid == ARBITRUM_SEPOLIA) {
            activeConfig = getArbitrumSepoliaConfig();
        } else {
            revert UnsupportedChainId(block.chainid);
        }
    }

    function getActiveConfig() public view returns (Config memory) {
        return activeConfig;
    }

    function getArbitrumOneMainnetConfig() public view returns (Config memory arbitrumOneMainnetConfig) {
        // TODO
    }

    function getArbitrumSepoliaConfig() public pure returns (Config memory) {
        address adminAddress = 0x7C046645E21B811780Cf420021E6701A9E66935C;
        address treasuryAddress = 0x310E2E738BC3654a221488d665a85C78D92317C1;

        /*//////////////////////////////////////////////////////////////
                           INITIALIZE PARAMS
        //////////////////////////////////////////////////////////////*/
        InitializeParams memory initializeParams = InitializeParams({
            admin: adminAddress, // Replace with actual admin address
            configSetter: adminAddress, // Replace with actual config setter address
            treasury: treasuryAddress, // Replace with actual treasury address
            proposalPassVetoThreshold: 0.05 * 10**18, // 5%
            minQuorumThreshold: 0.05 * 10**18, // 5%
            voteActivationDelay: 5 minutes,
            voteDuration: 15 minutes,
            proposalDuration: 30 minutes,
            maxRPCUrlsPerChain: 2,
            pcrConfig: IGovernanceTypes.PCR({
                pcr0: hex"7500231dcae6dc3742b53d81b7553fd401a299fb5c9eaca2a7c3601cc63e5f733a921522f34ab5d0de767435c236f39d",
                pcr1: hex"3d9be02ba042fe48bc94881586fd57f6006260f05f7b56ed4e14cac66ab03b1f755825f334aa4b5a4b14cddc7a56fb32",
                pcr2: hex"af37246113559575edac229e1f99c08c465824d62e99978994fc8e24c7cdab2379d67f0a6fdd83cfe9d3ec70acc406d8"
            }),
            kmsRootServerPubKey: hex"14eadecaec620fac17b084dcd423b0a75ed2c248b0f73be1bb9b408476567ffc221f420612dd995555650dc19dbe972e7277cb6bfe5ce26650ec907be759b276",
            kmsPath: "gov_key" 
        });

        /*//////////////////////////////////////////////////////////////
                          TOKEN NETWORK CONFIG
        //////////////////////////////////////////////////////////////*/
        TokenNetworkConfig[] memory governanceNetworkConfigs = new TokenNetworkConfig[](2);

        // Ethereum Sepolia
        string[] memory rpcUrlsEthereumSepolia = new string[](1);
        rpcUrlsEthereumSepolia[0] = "https://eth-sepolia.g.alchemy.com/v2/";
        governanceNetworkConfigs[1] = TokenNetworkConfig({
            chainId: ETHEREUM_SEPOLIA,
            tokenAddress: address(0xFF25f1caeFDdaacf7067940b04012aAcdeAE2d68), // "Governance Token" in "Ethereum Sepolia"
            rpcUrls: rpcUrlsEthereumSepolia
        });

        // Arbitrum Sepolia
        string[] memory rpcUrlsArbitrumSepolia = new string[](1);
        rpcUrlsArbitrumSepolia[0] = "https://arb-sepolia.g.alchemy.com/v2/";
        governanceNetworkConfigs[0] = TokenNetworkConfig({
            chainId: ARBITRUM_SEPOLIA,
            tokenAddress: address(0x9E72284B0E205b592731C30EBb8064E853FEe3E8), // "Governance Token" in "Arbitrum Sepolia"
            rpcUrls: rpcUrlsArbitrumSepolia
        });


        /*//////////////////////////////////////////////////////////////
                           TOKEN LOCK CONFIG
        //////////////////////////////////////////////////////////////*/
        TokenLockConfig[] memory tokenLockConfigs = new TokenLockConfig[](1);
        tokenLockConfigs[0] = TokenLockConfig({
            tokenAddress: address(0x5C891c16bdC9bBA00707f2aDbeBe3AF52D180Fa9), // T"Deposit Token" in "Arbitrum Sepolia"
            lockAmount: 100 * 10**18 // 10 tokens
        });


        /*//////////////////////////////////////////////////////////////
                                RETURN CONFIGS
        //////////////////////////////////////////////////////////////*/
        return Config({
            initializeParams: initializeParams,
            tokenLockConfigs: tokenLockConfigs,
            governanceNetworkConfigs: governanceNetworkConfigs
        });
    }
    
}