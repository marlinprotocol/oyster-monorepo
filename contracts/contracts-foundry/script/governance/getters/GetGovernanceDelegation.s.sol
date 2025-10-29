// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {GovernanceDelegation} from "../../../src/governance/GovernanceDelegation.sol";

contract GetGovernanceDelegationBase is Script {
    
    GovernanceDelegation public governanceDelegation;

    constructor() {
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, ".json");
        string memory json = vm.readFile(filePath);
        
        address governanceDelegationProxy = vm.parseJsonAddress(json, ".GovernanceDelegation.proxy");
        governanceDelegation = GovernanceDelegation(governanceDelegationProxy);
        
        console.log("Loaded GovernanceDelegation proxy:", governanceDelegationProxy);
    }
}

// forge script script/governance/getters/GetGovernanceDelegation.s.sol:GetDelegation --rpc-url <RPC_URL> -vvv
contract GetDelegation is GetGovernanceDelegationBase {
    
    address constant DELEGATOR_ADDRESS = 0x0000000000000000000000000000000000000000;
    
    function run() external view {
        address delegatee = governanceDelegation.delegations(DELEGATOR_ADDRESS);
        console.log("Delegation for delegator:", DELEGATOR_ADDRESS);
        console.log("  Delegatee:", delegatee);
    }
}

