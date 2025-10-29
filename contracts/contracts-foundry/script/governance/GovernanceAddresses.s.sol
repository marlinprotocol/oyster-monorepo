// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";

contract GovernanceAddresses is Script {
    
    string internal addressesJson;
    
    constructor() {
        // Read deployed addresses from JSON
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, ".json");
        addressesJson = vm.readFile(filePath);
    }
}