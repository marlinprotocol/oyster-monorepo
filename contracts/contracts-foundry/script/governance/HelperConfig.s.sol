// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";

/**
 * @notice Helper config for Governance deployment
 * @dev Automatically detects chain ID and returns appropriate configuration
 */
contract HelperConfig is Script {

    // ========== Structs ==========

    struct GovernanceInitParams {
        address admin;
        address configSetter;
        address treasury;
        address governanceEnclave;
        uint256 minQuorumThreshold;
        uint256 proposalPassVetoThreshold;
        uint256 vetoSlashRate;
        uint256 voteActivationDelay;
        uint256 voteDuration;
        uint256 proposalDuration;
    }
    
    struct GovernanceEnclaveInitParams {
        address admin;
        bytes kmsRootServerPubKey;
        bytes pcr0;
        bytes pcr1;
        bytes pcr2;
        uint256 maxRPCUrlsPerChain;
    }

    struct GovernanceDelegationInitParams {
        address admin;
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

    struct DelegationChainConfig {
        uint256 chainId;
        address governanceDelegation;
    }

    // ========== Constants ==========

    uint256 public constant ARBITRUM_ONE_MAINNET = 42161;
    uint256 public constant ARBITRUM_SEPOLIA = 421614;
    uint256 public constant ETHEREUM_SEPOLIA = 11155111;

    error UnsupportedChainId(uint256 chainId);

    // ========== Virtual Functions (to be overridden) ==========

    function getGovernanceInitParams() public pure virtual returns (GovernanceInitParams memory) {
        revert("HelperConfig: Must be overridden");
    }

    function getGovernanceEnclaveInitParams() public pure virtual returns (GovernanceEnclaveInitParams memory) {
        revert("HelperConfig: Must be overridden");
    }

    function getGovernanceDelegationInitParams() public pure virtual returns (GovernanceDelegationInitParams memory) {
        revert("HelperConfig: Must be overridden");
    }

    function getTokenLockConfigs() public pure virtual returns (TokenLockConfig[] memory) {
        revert("HelperConfig: Must be overridden");
    }

    function getDelegationChainConfigs() public pure virtual returns (DelegationChainConfig[] memory) {
        revert("HelperConfig: Must be overridden");
    }

    function getNetworkConfigs() public pure virtual returns (TokenNetworkConfig[] memory) {
        revert("HelperConfig: Must be overridden");
    }

    function getDepositTokenAddress() public pure virtual returns (address) {
        revert("HelperConfig: Must be overridden");
    }

    function getGovernanceTokenAddress() public pure virtual returns (address) {
        revert("HelperConfig: Must be overridden");
    }
}

/**
 * @notice Arbitrum Sepolia configuration
 */
contract ArbitrumSepoliaConfig is HelperConfig {

    address constant ADMIN = 0x7E82Da6A7D4f9Bcc01372e8Fe2E882e18fAd9C5A;
    address constant TREASURY = 0x7E82Da6A7D4f9Bcc01372e8Fe2E882e18fAd9C5A;
    
    // Token addresses
    address constant DEPOSIT_TOKEN_ARBITRUM_SEPOLIA = 0xc5b41bD20808B4695CBf402AD27d608673FDC888;
    address constant GOVERNANCE_TOKEN_ARBITRUM_SEPOLIA = 0x0a3ae3C1F42Ea9AD5C1fB1A62796735C13801890;
    address constant GOVERNANCE_TOKEN_ETHEREUM_SEPOLIA = 0x2e91E10a9144C2a74F73E745887f89D255817A3e;

    // KMS Configuration
    bytes constant KMS_ROOT_SERVER_PUB_KEY = hex"14eadecaec620fac17b084dcd423b0a75ed2c248b0f73be1bb9b408476567ffc221f420612dd995555650dc19dbe972e7277cb6bfe5ce26650ec907be759b276";
    bytes constant PCR0 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant PCR1 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant PCR2 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    function getGovernanceInitParams() public pure override returns (GovernanceInitParams memory) {
        return GovernanceInitParams({
            admin: ADMIN,
            configSetter: ADMIN,
            treasury: TREASURY,
            governanceEnclave: address(0), // Will be set after GovernanceEnclave deployment
            minQuorumThreshold: 0.05 * 1e18, // 5%
            proposalPassVetoThreshold: 0.05 * 1e18, // 5%
            vetoSlashRate: 0.3 * 1e18, // 30%
            voteActivationDelay: 5 minutes,
            voteDuration: 15 minutes,
            proposalDuration: 30 minutes
        });
    }

    function getGovernanceEnclaveInitParams() public pure override returns (GovernanceEnclaveInitParams memory) {
        return GovernanceEnclaveInitParams({
            admin: ADMIN,
            kmsRootServerPubKey: KMS_ROOT_SERVER_PUB_KEY,
            pcr0: PCR0,
            pcr1: PCR1,
            pcr2: PCR2,
            maxRPCUrlsPerChain: 10
        });
    }

    function getGovernanceDelegationInitParams() public pure override returns (GovernanceDelegationInitParams memory) {
        return GovernanceDelegationInitParams({
            admin: ADMIN
        });
    }

    function getTokenLockConfigs() public pure override returns (TokenLockConfig[] memory) {
        TokenLockConfig[] memory configs = new TokenLockConfig[](1);
        configs[0] = TokenLockConfig({
            tokenAddress: DEPOSIT_TOKEN_ARBITRUM_SEPOLIA,
            lockAmount: 100 * 1e18
        });
        return configs;
    }

    function getDelegationChainConfigs() public pure override returns (DelegationChainConfig[] memory) {
        DelegationChainConfig[] memory configs = new DelegationChainConfig[](1);
        configs[0] = DelegationChainConfig({
            chainId: ARBITRUM_SEPOLIA,
            governanceDelegation: address(0) // Will be set after GovernanceDelegation deployment
        });
        return configs;
    }

    function getNetworkConfigs() public pure override returns (TokenNetworkConfig[] memory) {
        TokenNetworkConfig[] memory configs = new TokenNetworkConfig[](2);
        
        // Arbitrum Sepolia
        string[] memory rpcUrlsArbitrumSepolia = new string[](1);
        rpcUrlsArbitrumSepolia[0] = "https://arb-sepolia.g.alchemy.com/v2/";
        configs[0] = TokenNetworkConfig({
            chainId: ARBITRUM_SEPOLIA,
            tokenAddress: GOVERNANCE_TOKEN_ARBITRUM_SEPOLIA,
            rpcUrls: rpcUrlsArbitrumSepolia
        });

        // Ethereum Sepolia
        string[] memory rpcUrlsEthereumSepolia = new string[](1);
        rpcUrlsEthereumSepolia[0] = "https://eth-sepolia.g.alchemy.com/v2/";
        configs[1] = TokenNetworkConfig({
            chainId: ETHEREUM_SEPOLIA,
            tokenAddress: GOVERNANCE_TOKEN_ETHEREUM_SEPOLIA,
            rpcUrls: rpcUrlsEthereumSepolia
        });

        return configs;
    }

    function getDepositTokenAddress() public pure override returns (address) {
        return DEPOSIT_TOKEN_ARBITRUM_SEPOLIA;
    }

    function getGovernanceTokenAddress() public pure override returns (address) {
        return GOVERNANCE_TOKEN_ARBITRUM_SEPOLIA;
    }
}

/**
 * @notice Ethereum Sepolia configuration
 */
contract EthereumSepoliaConfig is HelperConfig {

    address constant ADMIN = 0x7C046645E21B811780Cf420021E6701A9E66935C;
    address constant TREASURY = 0x310E2E738BC3654a221488d665a85C78D92317C1;
    
    // Token addresses
    address constant DEPOSIT_TOKEN_ETHEREUM_SEPOLIA = 0xc5b41bD20808B4695CBf402AD27d608673FDC888;
    address constant GOVERNANCE_TOKEN_ETHEREUM_SEPOLIA = 0x6965eC94b4a2D064276b61B35fBdba22e4f99807;
    address constant GOVERNANCE_TOKEN_ARBITRUM_SEPOLIA = 0x0a3ae3C1F42Ea9AD5C1fB1A62796735C13801890;

    // KMS Configuration
    bytes constant KMS_ROOT_SERVER_PUB_KEY = hex"d8ad28c9f74e8bf4eb9199e638b2df049282e9c28e40edd096b443ef95b3b829ed785629e1aab7ce66459c76c9888ea26a8eae3a401ac6532824bde249b3292e";
    bytes constant PCR0 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant PCR1 = hex"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    bytes constant PCR2 = hex"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

    function getGovernanceInitParams() public pure override returns (GovernanceInitParams memory) {
        return GovernanceInitParams({
            admin: ADMIN,
            configSetter: ADMIN,
            treasury: TREASURY,
            governanceEnclave: address(0), // Will be set after GovernanceEnclave deployment
            minQuorumThreshold: 0.05 * 1e18, // 5%
            proposalPassVetoThreshold: 0.05 * 1e18, // 5%
            vetoSlashRate: 0.3 * 1e18, // 30%
            voteActivationDelay: 5 minutes,
            voteDuration: 15 minutes,
            proposalDuration: 30 minutes
        });
    }

    function getGovernanceEnclaveInitParams() public pure override returns (GovernanceEnclaveInitParams memory) {
        return GovernanceEnclaveInitParams({
            admin: ADMIN,
            kmsRootServerPubKey: KMS_ROOT_SERVER_PUB_KEY,
            pcr0: PCR0,
            pcr1: PCR1,
            pcr2: PCR2,
            maxRPCUrlsPerChain: 10
        });
    }

    function getGovernanceDelegationInitParams() public pure override returns (GovernanceDelegationInitParams memory) {
        return GovernanceDelegationInitParams({
            admin: ADMIN
        });
    }

    function getTokenLockConfigs() public pure override returns (TokenLockConfig[] memory) {
        TokenLockConfig[] memory configs = new TokenLockConfig[](1);
        configs[0] = TokenLockConfig({
            tokenAddress: DEPOSIT_TOKEN_ETHEREUM_SEPOLIA,
            lockAmount: 100 * 1e18
        });
        return configs;
    }

    function getDelegationChainConfigs() public pure override returns (DelegationChainConfig[] memory) {
        DelegationChainConfig[] memory configs = new DelegationChainConfig[](1);
        configs[0] = DelegationChainConfig({
            chainId: ETHEREUM_SEPOLIA,
            governanceDelegation: address(0) // Will be set after GovernanceDelegation deployment
        });
        return configs;
    }

    function getNetworkConfigs() public pure override returns (TokenNetworkConfig[] memory) {
        TokenNetworkConfig[] memory configs = new TokenNetworkConfig[](2);

        // Ethereum Sepolia
        string[] memory rpcUrlsEthereumSepolia = new string[](1);
        rpcUrlsEthereumSepolia[0] = "https://eth-sepolia.g.alchemy.com/v2/";
        configs[0] = TokenNetworkConfig({
            chainId: ETHEREUM_SEPOLIA,
            tokenAddress: GOVERNANCE_TOKEN_ETHEREUM_SEPOLIA,
            rpcUrls: rpcUrlsEthereumSepolia
        });

        // Arbitrum Sepolia (cross-chain)
        string[] memory rpcUrlsArbitrumSepolia = new string[](1);
        rpcUrlsArbitrumSepolia[0] = "https://arb-sepolia.g.alchemy.com/v2/";
        configs[1] = TokenNetworkConfig({
            chainId: ARBITRUM_SEPOLIA,
            tokenAddress: GOVERNANCE_TOKEN_ARBITRUM_SEPOLIA,
            rpcUrls: rpcUrlsArbitrumSepolia
        });

        return configs;
    }

    function getDepositTokenAddress() public pure override returns (address) {
        return DEPOSIT_TOKEN_ETHEREUM_SEPOLIA;
    }

    function getGovernanceTokenAddress() public pure override returns (address) {
        return GOVERNANCE_TOKEN_ETHEREUM_SEPOLIA;
    }
}

/**
 * @notice Factory for creating chain-specific HelperConfig
 */
contract ConfigFactory is Script {
    
    uint256 constant ARBITRUM_SEPOLIA = 421614;
    uint256 constant ETHEREUM_SEPOLIA = 11155111;
    
    error UnsupportedChainId(uint256 chainId);

    function getConfig() public returns (HelperConfig) {
        if (block.chainid == ARBITRUM_SEPOLIA) {
            return HelperConfig(address(new ArbitrumSepoliaConfig()));
        } else if (block.chainid == ETHEREUM_SEPOLIA) {
            return HelperConfig(address(new EthereumSepoliaConfig()));
        } else {
            revert UnsupportedChainId(block.chainid);
        }
    }
}

