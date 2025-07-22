// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {GovernanceInteraction} from "./GovernanceInteraction.s.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";
import {console} from "forge-std/console.sol";

contract GovernanceInteractionResultSubmitter is Script, GovernanceInteraction {
    constructor() {}

    // Submits the result for a given proposalId and related data from JSON
    function submitResultByIndex(uint256 idx) public {
        // Read JSON file
        string memory json = vm.readFile("../inputs/results.json");
        string memory base = string.concat("[", vm.toString(idx), "]");

        // Parse fields from JSON
        bytes32 proposalId = vm.parseJsonBytes32(json, string.concat(base, ".proposalId"));
        bytes memory kmsSig = vm.parseJsonBytes(json, string.concat(base, ".kmsSig"));
        bytes memory enclavePubKey = vm.parseJsonBytes(json, string.concat(base, ".enclavePubKey"));
        bytes memory enclaveSig = vm.parseJsonBytes(json, string.concat(base, ".enclaveSig"));
        bytes memory resultData = vm.parseJsonBytes(json, string.concat(base, ".resultData"));

        IGovernanceTypes.SubmitResultInputParams memory params = IGovernanceTypes.SubmitResultInputParams({
            kmsSig: kmsSig,
            enclavePubKey: enclavePubKey,
            enclaveSig: enclaveSig,
            resultData: resultData
        });

        // Read private key from .env
        uint256 submitterPrivateKey = vm.envUint("SUBMITTER_PRIVATE_KEY");

        // Broadcast the transaction using the submitter's private key
        vm.startBroadcast(submitterPrivateKey);
        governance.submitResult(params);
        vm.stopBroadcast();

        console.log("Result submitted successfully!");
        console.log("proposalId:");
        console.logBytes32(proposalId);
    }

    // Entrypoint for Foundry script execution
    function run() external {
        uint256 idx = vm.envUint("RESULT_INDEX");
        submitResultByIndex(idx);
    }
}
