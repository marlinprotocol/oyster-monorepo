// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {GovernanceDelegation} from "../../../src/governance/GovernanceDelegation.sol";

contract SetGovernanceDelegationBase is Script {
    
    GovernanceDelegation public governanceDelegation;

    constructor() {
        // Read deployed addresses from JSON
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, "/address.json");
        string memory json = vm.readFile(filePath);
        
        address governanceDelegationProxy = vm.parseJsonAddress(json, ".GovernanceDelegation.proxy");
        governanceDelegation = GovernanceDelegation(governanceDelegationProxy);
        
        console.log("Loaded GovernanceDelegation proxy:", governanceDelegationProxy);
    }
}

// forge script script/governance/setters/SetGovernanceDelegation.s.sol:SetDelegation --rpc-url <RPC_URL> --broadcast
contract SetDelegation is SetGovernanceDelegationBase {
    
    address constant DELEGATEE_ADDRESS = 0x0000000000000000000000000000000000000000; // Update this
    
    function run() external {
        vm.startBroadcast();
        governanceDelegation.setDelegation(DELEGATEE_ADDRESS);
        vm.stopBroadcast();
        
        console.log("Delegation set to:", DELEGATEE_ADDRESS);
        console.log("Delegator:", msg.sender);
    }
}

// forge script script/governance/setters/SetGovernanceDelegation.s.sol:RemoveDelegation --rpc-url <RPC_URL> --broadcast
contract RemoveDelegation is SetGovernanceDelegationBase {
    function run() external {
        vm.startBroadcast();
        governanceDelegation.setDelegation(address(0));
        vm.stopBroadcast();
        
        console.log("Delegation removed (set to address(0))");
        console.log("Delegator:", msg.sender);
    }
}

