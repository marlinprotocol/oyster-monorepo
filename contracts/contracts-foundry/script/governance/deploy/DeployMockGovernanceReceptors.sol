// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {MockGovernanceReceptor} from "../../../src/governance/mocks/MockGovernanceReceptor.sol";
import {console} from "forge-std/console.sol";

contract DeployMockGovernanceReceptor is Script {
    function run() external returns (address) {
        address mockErc20 = deployMockGovernanceReceptor();
        return mockErc20;
    }

    function deployMockGovernanceReceptor() public returns (address) {
        vm.startBroadcast();

        MockGovernanceReceptor mock = new MockGovernanceReceptor();

        vm.stopBroadcast();

        console.log("MockGovernanceReceptor deployed at:", address(mock));

        return address(mock);
    }
}
