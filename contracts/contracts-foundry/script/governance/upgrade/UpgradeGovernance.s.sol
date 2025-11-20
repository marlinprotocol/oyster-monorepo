// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {GovernanceEnclave} from "../../../src/governance/GovernanceEnclave.sol";
import {GovernanceDelegation} from "../../../src/governance/GovernanceDelegation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {HelperConfig} from "../HelperConfig.s.sol";

/**
 * @notice Upgrades Governance-related contracts by deploying new implementations
 * @dev Reads existing proxy addresses from addresses/{chainId}/address.json and updates them
 *
 * Usage:
 *   Upgrade all contracts:
 *     forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceAll --rpc-url <RPC_URL> --broadcast
 *
 *   Upgrade individual contracts:
 *     Governance only (vote hash logic update):
 *       forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceContract --rpc-url <RPC_URL> --broadcast
 *
 *     GovernanceEnclave only:
 *       forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceEnclaveContract --rpc-url <RPC_URL> --broadcast
 *
 *     GovernanceDelegation only:
 *       forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceDelegationContract --rpc-url <RPC_URL> --broadcast
 */
contract UpgradeGovernanceBase is Script {
    struct DeployedAddresses {
        address governanceProxy;
        address governanceImplementation;
        address governanceEnclaveProxy;
        address governanceEnclaveImplementation;
        address governanceDelegationProxy;
        address governanceDelegationImplementation;
        address depositToken;
        address governanceToken;
    }

    DeployedAddresses public deployed;

    function loadDeployedAddresses() internal {
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, "/address.json");

        string memory json = vm.readFile(filePath);

        deployed.governanceProxy = vm.parseJsonAddress(json, ".Governance.proxy");
        deployed.governanceImplementation = vm.parseJsonAddress(json, ".Governance.implementation");
        deployed.governanceEnclaveProxy = vm.parseJsonAddress(json, ".GovernanceEnclave.proxy");
        deployed.governanceEnclaveImplementation = vm.parseJsonAddress(json, ".GovernanceEnclave.implementation");
        deployed.governanceDelegationProxy = vm.parseJsonAddress(json, ".GovernanceDelegation.proxy");
        deployed.governanceDelegationImplementation = vm.parseJsonAddress(json, ".GovernanceDelegation.implementation");
        deployed.depositToken = vm.parseJsonAddress(json, ".tokens.deposit");
        deployed.governanceToken = vm.parseJsonAddress(json, ".tokens.governance");

        console.log("Loaded deployed addresses from:", filePath);
    }

    function saveDeployedAddresses() internal {
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
        string memory governanceJson = vm.serializeAddress(objectKey, "proxy", deployed.governanceProxy);
        governanceJson = vm.serializeAddress(objectKey, "implementation", deployed.governanceImplementation);

        string memory finalJson = vm.serializeString("root", "Governance", governanceJson);

        // GovernanceEnclave
        string memory enclaveJson = vm.serializeAddress("enclave", "proxy", deployed.governanceEnclaveProxy);
        enclaveJson = vm.serializeAddress("enclave", "implementation", deployed.governanceEnclaveImplementation);

        finalJson = vm.serializeString("root", "GovernanceEnclave", enclaveJson);

        // GovernanceDelegation
        string memory delegationJson = vm.serializeAddress("delegation", "proxy", deployed.governanceDelegationProxy);
        delegationJson =
            vm.serializeAddress("delegation", "implementation", deployed.governanceDelegationImplementation);

        finalJson = vm.serializeString("root", "GovernanceDelegation", delegationJson);

        // Tokens
        string memory tokensJson = vm.serializeAddress("tokens", "deposit", deployed.depositToken);
        tokensJson = vm.serializeAddress("tokens", "governance", deployed.governanceToken);

        finalJson = vm.serializeString("root", "tokens", tokensJson);

        // Write to file
        vm.writeJson(finalJson, filePath);

        console.log("Updated addresses saved to:", filePath);
    }

    function upgradeGovernance() public {
        console.log("=== Upgrading Governance ===");

        // Deploy new implementation
        Governance newImplementation = new Governance();
        console.log("New Governance Implementation:", address(newImplementation));
        console.log("Existing Governance Proxy:", deployed.governanceProxy);

        // Upgrade proxy to new implementation
        UUPSUpgradeable(payable(deployed.governanceProxy)).upgradeTo(address(newImplementation));
        console.log("Governance upgraded successfully");

        // Update stored address
        deployed.governanceImplementation = address(newImplementation);
    }

    function upgradeGovernanceEnclave() public {
        console.log("=== Upgrading GovernanceEnclave ===");

        // Deploy new implementation
        GovernanceEnclave newImplementation = new GovernanceEnclave();
        console.log("New GovernanceEnclave Implementation:", address(newImplementation));
        console.log("Existing GovernanceEnclave Proxy:", deployed.governanceEnclaveProxy);

        // Upgrade proxy to new implementation
        UUPSUpgradeable(payable(deployed.governanceEnclaveProxy)).upgradeTo(address(newImplementation));
        console.log("GovernanceEnclave upgraded successfully");

        // Update stored address
        deployed.governanceEnclaveImplementation = address(newImplementation);
    }

    function upgradeGovernanceDelegation() public {
        console.log("=== Upgrading GovernanceDelegation ===");

        // Deploy new implementation
        GovernanceDelegation newImplementation = new GovernanceDelegation();
        console.log("New GovernanceDelegation Implementation:", address(newImplementation));
        console.log("Existing GovernanceDelegation Proxy:", deployed.governanceDelegationProxy);

        // Upgrade proxy to new implementation
        UUPSUpgradeable(payable(deployed.governanceDelegationProxy)).upgradeTo(address(newImplementation));
        console.log("GovernanceDelegation upgraded successfully");

        // Update stored address
        deployed.governanceDelegationImplementation = address(newImplementation);
    }
}

/**
 * @notice Upgrade all Governance contracts
 *
 * USAGE:
 * forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceAll --rpc-url <RPC_URL> --broadcast
 */
contract UpgradeGovernanceAll is UpgradeGovernanceBase {
    function run() external {
        loadDeployedAddresses();

        vm.startBroadcast();

        upgradeGovernanceEnclave();
        console.log("");

        upgradeGovernanceDelegation();
        console.log("");

        upgradeGovernance();
        console.log("");

        vm.stopBroadcast();

        saveDeployedAddresses();

        console.log("");
        console.log("=== All Upgrades Complete ===");
    }
}

/**
 * @notice Upgrade Governance contract only
 * @dev This upgrades the Governance contract with the new vote hash calculation logic:
 *      - voteEncrypted is first hashed with sha256()
 *      - Then encoded with voter, delegator, delegatorChainId
 *      - More gas efficient than encoding voteEncrypted directly
 *
 * USAGE:
 * Arbitrum Sepolia: forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceContract --rpc-url $ARBITRUM_SEPOLIA_RPC_URL --broadcast
 */
contract UpgradeGovernanceContract is UpgradeGovernanceBase {
    function run() external {
        loadDeployedAddresses();

        vm.startBroadcast();
        upgradeGovernance();
        vm.stopBroadcast();

        saveDeployedAddresses();

        console.log("");
        console.log("=== Governance Upgrade Complete ===");
    }
}

/**
 * @notice Upgrade GovernanceEnclave contract only
 *
 * USAGE:
 * Arbitrum Sepolia: forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceEnclaveContract --rpc-url $ARBITRUM_SEPOLIA_RPC_URL --broadcast
 */
contract UpgradeGovernanceEnclaveContract is UpgradeGovernanceBase {
    function run() external {
        loadDeployedAddresses();

        vm.startBroadcast();
        upgradeGovernanceEnclave();
        vm.stopBroadcast();

        saveDeployedAddresses();

        console.log("");
        console.log("=== GovernanceEnclave Upgrade Complete ===");
    }
}

/**
 * @notice Upgrade GovernanceDelegation contract only
 *
 * USAGE:
 * forge script script/governance/upgrade/UpgradeGovernance.s.sol:UpgradeGovernanceDelegationContract --rpc-url <RPC_URL> --broadcast
 */
contract UpgradeGovernanceDelegationContract is UpgradeGovernanceBase {
    function run() external {
        loadDeployedAddresses();

        vm.startBroadcast();
        upgradeGovernanceDelegation();
        vm.stopBroadcast();

        saveDeployedAddresses();

        console.log("");
        console.log("=== GovernanceDelegation Upgrade Complete ===");
    }
}
