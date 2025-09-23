// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {GovernanceInteraction} from "./GovernanceInteraction.s.sol";
import {console} from "forge-std/console.sol";

contract GovernanceInteractionVoter is GovernanceInteraction {
    constructor() {}

    // Reads votes.json and votes for the given voteEncrypted key and vote index
    function voteByProposalId(string memory voter, bytes32 proposalId, uint256 voteIndex) public {
        string memory json = vm.readFile("script/governance/interactions/inputs/votes.json");
        
        // Use voteEncrypted value as key to access the vote
        string memory voteEncryptedKey = vm.toString(proposalId);
        string memory base = string.concat(".", voteEncryptedKey, "[", vm.toString(voteIndex), "]");

        bytes memory voteEncrypted = vm.parseJsonBytes(json, string.concat(base, ".voteEncrypted"));

        // Submit Tx
        uint256 voterPrivateKey = vm.envUint(voter);
        vm.startBroadcast(voterPrivateKey);
        governance.vote(proposalId, voteEncrypted, address(0), 0);
        vm.stopBroadcast();

        console.log("Vote submitted successfully!\n");
        console.log("proposalId:");
        console.logBytes32(proposalId);
        console.log("voteEncrypted:");
        console.logBytes(voteEncrypted);
    }

    // Entrypoint for Foundry script execution
    function run() external {
        string memory voter = vm.envString("VOTER");
        bytes32 proposalId = 0x541c9ed73525aee08e5767948513456f938b7f044e9059d6ad85568d0ba1d81b;
        uint256 voteIndex = vm.envUint("VOTE_INDEX");
        console.log("Voting for proposal:");
        console.logBytes32(proposalId);
        console.log("Vote index:", voteIndex);
        voteByProposalId(voter, proposalId, voteIndex);
    }
}