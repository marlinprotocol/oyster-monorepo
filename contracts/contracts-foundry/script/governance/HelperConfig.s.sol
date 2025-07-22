// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {Governance} from "../../src/governance/Governance.sol";

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
        // KMS related parameters
        IGovernanceTypes.PCR pcr;
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

    uint256 public constant ARBITRUM_ONE_MAINNET = 42161;
    uint256 public constant ARBITRUM_SEPOLIA = 421614;
    uint256 public constant ETHEREUM_SEPOLIA = 11155111;

    Config public activeConfig;
    Governance public governance;

    constructor() {
        if(block.chainid == ARBITRUM_ONE_MAINNET) {
            activeConfig = getArbitrumOneMainnetConfig();
        } else if (block.chainid == ARBITRUM_SEPOLIA) {
            activeConfig = getArbitrumSepoliaConfig();
            governance = Governance(0x5A4cDc889698a42D7DFE0C15da3adCF41E3db138); // "Governance" in "Arbitrum Sepolia"
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
        /* 21/07/2025 */
        // TODO: parse json
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
            pcr: IGovernanceTypes.PCR({
                pcr0: hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                pcr1: hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                pcr2: hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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
            tokenAddress: address(0x6965eC94b4a2D064276b61B35fBdba22e4f99807), // "Governance Token" in "Ethereum Sepolia"
            rpcUrls: rpcUrlsEthereumSepolia
        });

        // Arbitrum Sepolia
        string[] memory rpcUrlsArbitrumSepolia = new string[](1);
        rpcUrlsArbitrumSepolia[0] = "https://arb-sepolia.g.alchemy.com/v2/";
        governanceNetworkConfigs[0] = TokenNetworkConfig({
            chainId: ARBITRUM_SEPOLIA,
            tokenAddress: address(0xCe815C7b2E4000f63146fF988F891D6335d262AE), // "Governance Token" in "Arbitrum Sepolia"
            rpcUrls: rpcUrlsArbitrumSepolia
        });


        /*//////////////////////////////////////////////////////////////
                           TOKEN LOCK CONFIG
        //////////////////////////////////////////////////////////////*/
        TokenLockConfig[] memory tokenLockConfigs = new TokenLockConfig[](1);
        tokenLockConfigs[0] = TokenLockConfig({
            tokenAddress: address(0x293A148f62665f77ed0f18FC20C66A696cc7632C), // "Deposit Token" in "Arbitrum Sepolia"
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