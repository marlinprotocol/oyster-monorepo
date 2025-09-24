// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20} from "../../../src/governance/mocks/MockERC20.sol";
import {HelperConfig} from "../HelperConfig.s.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract ERC20Mint is Script, HelperConfig {

    function run() public {
        
    }


    function _mintGovernanceToken() internal {
        address recipient = vm.envAddress("GOVERNANCE_TOKEN_RECIPIENT");

        vm.startBroadcast();
        governanceToken.mint(recipient, 1000000000000000000000000000000000000000);
        vm.stopBroadcast();
    }
}