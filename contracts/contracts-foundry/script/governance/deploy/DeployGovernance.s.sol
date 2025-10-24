// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {GovernanceEnclave} from "../../../src/governance/GovernanceEnclave.sol";
import {GovernanceDelegation} from "../../../src/governance/GovernanceDelegation.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HelperConfig, ConfigFactory} from "../HelperConfig.s.sol";

/**
 * @notice Deploys all Governance-related contracts: GovernanceEnclave, GovernanceDelegation, and Governance
 * @dev Automatically detects chain ID and uses appropriate configuration
 * 
 * Usage:
 *   forge script script/governance/DeployGovernance.s.sol:DeployGovernance --rpc-url $RPC_URL --broadcast --verify
 */
contract DeployGovernance is Script {

    // Proxy addresses
    address public governanceEnclaveProxy;
    address public governanceDelegationProxy;
    address public governanceProxy;

    // Implementation addresses
    address public governanceEnclaveImplementation;
    address public governanceDelegationImplementation;
    address public governanceImplementation;

    function run() external {
        // Auto-detect chain and get appropriate config
        ConfigFactory factory = new ConfigFactory();
        HelperConfig helperConfig = factory.getConfig();
        
        deploy(helperConfig);
    }

    function deploy(HelperConfig helperConfig) public {
        console.log("=== Deploying Governance System ===");
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast();

        // 1. Deploy GovernanceEnclave
        governanceEnclaveProxy = _deployGovernanceEnclave(helperConfig);
        console.log("");

        // 2. Deploy GovernanceDelegation
        governanceDelegationProxy = _deployGovernanceDelegation(helperConfig);
        console.log("");

        // 3. Deploy Governance
        governanceProxy = _deployGovernance(helperConfig, governanceEnclaveProxy);
        console.log("");

        // 4. Post-deployment configuration
        _configureContracts(helperConfig);

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Complete ===");
        console.log("GovernanceEnclave Proxy:", governanceEnclaveProxy);
        console.log("GovernanceDelegation Proxy:", governanceDelegationProxy);
        console.log("Governance Proxy:", governanceProxy);

        // 5. Save deployed addresses
        _saveDeployedAddresses(helperConfig);
    }

    function _saveDeployedAddresses(HelperConfig helperConfig) internal {
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory dirPath = string.concat(root, "/script/governance/addresses/", chainIdStr);
        string memory filePath = string.concat(dirPath, "/address.json");

        // Create directory if it doesn't exist
        string[] memory mkdirCmd = new string[](3);
        mkdirCmd[0] = "mkdir";
        mkdirCmd[1] = "-p";
        mkdirCmd[2] = dirPath;
        vm.ffi(mkdirCmd);

        // Build JSON using vm.serializeJson
        string memory objectKey = "deployment";
        
        // Governance
        string memory governanceJson = vm.serializeAddress(objectKey, "proxy", governanceProxy);
        governanceJson = vm.serializeAddress(objectKey, "implementation", governanceImplementation);
        
        string memory finalJson = vm.serializeString("root", "Governance", governanceJson);
        
        // GovernanceEnclave
        string memory enclaveJson = vm.serializeAddress("enclave", "proxy", governanceEnclaveProxy);
        enclaveJson = vm.serializeAddress("enclave", "implementation", governanceEnclaveImplementation);
        
        finalJson = vm.serializeString("root", "GovernanceEnclave", enclaveJson);
        
        // GovernanceDelegation
        string memory delegationJson = vm.serializeAddress("delegation", "proxy", governanceDelegationProxy);
        delegationJson = vm.serializeAddress("delegation", "implementation", governanceDelegationImplementation);
        
        finalJson = vm.serializeString("root", "GovernanceDelegation", delegationJson);
        
        // Tokens
        string memory tokensJson = vm.serializeAddress("tokens", "deposit", helperConfig.getDepositTokenAddress());
        tokensJson = vm.serializeAddress("tokens", "governance", helperConfig.getGovernanceTokenAddress());
        
        finalJson = vm.serializeString("root", "tokens", tokensJson);

        // Write to file
        vm.writeJson(finalJson, filePath);
        
        console.log("");
        console.log("Deployed addresses saved to:", filePath);
    }

    function _deployGovernanceEnclave(HelperConfig helperConfig) internal returns (address) {
        console.log("--- Deploying GovernanceEnclave ---");

        HelperConfig.GovernanceEnclaveInitParams memory params = helperConfig.getGovernanceEnclaveInitParams();

        // Deploy implementation
        GovernanceEnclave implementation = new GovernanceEnclave();
        governanceEnclaveImplementation = address(implementation);
        console.log("GovernanceEnclave Implementation:", address(implementation));

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), "");
        console.log("GovernanceEnclave Proxy:", address(proxy));

        // Initialize
        GovernanceEnclave(address(proxy)).initialize(
            params.admin,
            params.kmsRootServerPubKey,
            params.pcr0,
            params.pcr1,
            params.pcr2,
            params.maxRPCUrlsPerChain
        );
        console.log("GovernanceEnclave Initialized");

        // Note: Network configs will be set in _configureContracts

        return address(proxy);
    }

    function _deployGovernanceDelegation(HelperConfig helperConfig) internal returns (address) {
        console.log("--- Deploying GovernanceDelegation ---");

        HelperConfig.GovernanceDelegationInitParams memory params = helperConfig.getGovernanceDelegationInitParams();

        // Deploy implementation
        GovernanceDelegation implementation = new GovernanceDelegation();
        governanceDelegationImplementation = address(implementation);
        console.log("GovernanceDelegation Implementation:", address(implementation));

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), "");
        console.log("GovernanceDelegation Proxy:", address(proxy));

        // Initialize
        GovernanceDelegation(address(proxy)).initialize(params.admin);
        console.log("GovernanceDelegation Initialized");

        return address(proxy);
    }

    function _deployGovernance(HelperConfig helperConfig, address _governanceEnclave) internal returns (address) {
        console.log("--- Deploying Governance ---");

        HelperConfig.GovernanceInitParams memory params = helperConfig.getGovernanceInitParams();

        // Deploy implementation
        Governance implementation = new Governance();
        governanceImplementation = address(implementation);
        console.log("Governance Implementation:", address(implementation));

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), "");
        console.log("Governance Proxy:", address(proxy));

        // Initialize with deployed GovernanceEnclave address
        Governance(address(proxy)).initialize(
            params.admin,
            params.configSetter,
            params.treasury,
            _governanceEnclave, // Use deployed GovernanceEnclave address
            params.minQuorumThreshold,
            params.proposalPassVetoThreshold,
            params.vetoSlashRate,
            params.voteActivationDelay,
            params.voteDuration,
            params.proposalDuration
        );
        console.log("Governance Initialized");

        return address(proxy);
    }

    function _configureContracts(HelperConfig helperConfig) internal {
        console.log("--- Post-Deployment Configuration ---");

        // Set network configs on GovernanceEnclave
        HelperConfig.TokenNetworkConfig[] memory networkConfigs = helperConfig.getNetworkConfigs();
        for (uint256 i = 0; i < networkConfigs.length; i++) {
            GovernanceEnclave(governanceEnclaveProxy).setNetworkConfig(
                networkConfigs[i].chainId,
                networkConfigs[i].tokenAddress,
                networkConfigs[i].rpcUrls
            );
            console.log("Network config set for chainId:", networkConfigs[i].chainId);
        }

        // Set token lock amounts
        HelperConfig.TokenLockConfig[] memory tokenLockConfigs = helperConfig.getTokenLockConfigs();
        for (uint256 i = 0; i < tokenLockConfigs.length; i++) {
            Governance(governanceProxy).setTokenLockAmount(
                tokenLockConfigs[i].tokenAddress,
                tokenLockConfigs[i].lockAmount
            );
            console.log("Token lock amount set for token:", tokenLockConfigs[i].tokenAddress);
        }

        // Add governance delegation for chains
        HelperConfig.DelegationChainConfig[] memory delegationChainConfigs = helperConfig.getDelegationChainConfigs();
        for (uint256 i = 0; i < delegationChainConfigs.length; i++) {
            // Use deployed GovernanceDelegation address
            Governance(governanceProxy).addGovernanceDelegation(
                delegationChainConfigs[i].chainId,
                governanceDelegationProxy
            );
            console.log("Governance delegation added for chainId:", delegationChainConfigs[i].chainId);
        }

        console.log("Post-deployment configuration complete");
    }
}

