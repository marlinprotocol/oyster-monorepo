// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {GovernanceInteraction} from "./GovernanceInteraction.s.sol";
import {console} from "forge-std/console.sol";

contract GovernanceInteractionVoter is GovernanceInteraction {
    constructor() {}

    // Reads votes.json and votes only the proposal at the given index
    function voteByIndex(string memory voter, uint256 idx) public {
        string memory json = vm.readFile("../inputs/votes.json");
        string memory base = string.concat("[", vm.toString(idx), "]");

        bytes32 proposalId = vm.parseJsonBytes32(json, string.concat(base, ".proposalId"));
        bytes memory voteEncrypted = vm.parseJsonBytes(json, string.concat(base, ".voteEncrypted"));

        // Submit Tx
        uint256 voterPrivateKey = vm.envUint(voter);
        vm.startBroadcast();
        governance.vote(proposalId, voteEncrypted);
        vm.stopBroadcast();

        console.log("Vote submitted successfully!\n");
        console.log("proposalId:");
        console.logBytes32(proposalId);
        console.log("voteEncrypted:");
        console.logBytes(voteEncrypted);
    }

    // Entrypoint for Foundry script execution
    function run() external {
        string memory voter = vm.envString("VOTER_KEY_NAME");
        uint256 idx = vm.envUint("VOTE_INDEX");
        console.log("Voting for proposal at index:", idx);
        voteByIndex(voter, idx);
    }
}