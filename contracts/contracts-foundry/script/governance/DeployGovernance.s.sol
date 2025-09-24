// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {Governance} from "../../src/governance/Governance.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {console} from "forge-std/console.sol";

/* 
    18/07/2025 Arbitrum Sepolia: 0xF27C5d12e12E53a63A146709DBb78619dd0EEA00
 */
contract DeployGovernance is Script {

    HelperConfig helperConfig;
    HelperConfig.Config activeConfig;

    constructor() {
        helperConfig = new HelperConfig();
        activeConfig = helperConfig.getActiveConfig();
    }

    function run() external returns (address) {
        address governanceProxy = deployGovernance();
        return governanceProxy;
    }

    function deployGovernance() public returns (address) {
        
        vm.startBroadcast();

        // Deploy Implementation
        Governance governance = new Governance();

        // Deploy Proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(governance), "");

        // Initialize Proxy
        Governance(address(proxy)).initialize(
            activeConfig.initializeParams.admin,
            activeConfig.initializeParams.configSetter,
            activeConfig.initializeParams.treasury,
            activeConfig.initializeParams.minQuorumThreshold,
            activeConfig.initializeParams.proposalPassVetoThreshold,
            activeConfig.initializeParams.vetoSlashRate,
            activeConfig.initializeParams.voteActivationDelay,
            activeConfig.initializeParams.voteDuration,
            activeConfig.initializeParams.proposalDuration,
            activeConfig.initializeParams.maxRPCUrlsPerChain,
            activeConfig.initializeParams.pcr,
            activeConfig.initializeParams.kmsRootServerPubKey,
            activeConfig.initializeParams.kmsPath
        );
        vm.stopBroadcast();

        console.log("Governance Implementation deployed at:", address(governance));
        console.log("Governance Proxy deployed at:", address(proxy));

        return address(governance);
    }

    function initializeGovernance(address governanceProxy, HelperConfig.InitializeParams memory initializeParams) public {
        Governance governance = Governance(governanceProxy);

        vm.startBroadcast();

        governance.initialize(
            initializeParams.admin,
            initializeParams.configSetter,
            initializeParams.treasury,
            initializeParams.minQuorumThreshold,
            initializeParams.proposalPassVetoThreshold,
            initializeParams.vetoSlashRate,
            initializeParams.voteActivationDelay,
            initializeParams.voteDuration,
            initializeParams.proposalDuration,
            initializeParams.maxRPCUrlsPerChain,
            initializeParams.pcr,
            initializeParams.kmsRootServerPubKey,
            initializeParams.kmsPath
        );

        vm.stopBroadcast();
    }
}