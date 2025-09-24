// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {console} from "forge-std/console.sol";

contract UpgradeGovernance is Script, HelperConfig {
    function run() external {
        upgradeGovernance();
    }

    function upgradeGovernance() public {
        address governanceProxy = address(governance);
        vm.startBroadcast();
        Governance governanceImpl = new Governance();
        UUPSUpgradeable(payable(governanceProxy)).upgradeTo(address(governanceImpl));

        // Governance(address(governance)).setPCRConfig(
        //     activeConfig.initializeParams.pcr.pcr0,
        //     activeConfig.initializeParams.pcr.pcr1,
        //     activeConfig.initializeParams.pcr.pcr2
        // );


        // // Set Token Network Configurations
        // for (uint256 i = 0; i < activeConfig.governanceNetworkConfigs.length; i++) {
        //     Governance(address(governance)).setNetworkConfig(
        //         activeConfig.governanceNetworkConfigs[i].chainId,
        //         activeConfig.governanceNetworkConfigs[i].tokenAddress,
        //         activeConfig.governanceNetworkConfigs[i].rpcUrls
        //     );
        // }
        vm.stopBroadcast();
    }
}
