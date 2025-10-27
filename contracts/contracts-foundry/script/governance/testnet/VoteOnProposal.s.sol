// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

/**
 * @notice Vote on a specific proposal with encrypted vote data
 * @dev Allows a voter to cast their vote on a specific proposal
 * 
 * USAGE:
 * forge script script/governance/testnet/VoteOnProposal.s.sol:VoteOnProposal --rpc-url $ARBITRUM_SEPOLIA_RPC_URL --broadcast
 */
contract VoteOnProposal is Script {
    // Contract addresses
    address constant GOVERNANCE_PROXY = 0x51De4205a95fC8B5Dc4a616E616945cfB00facfd;
    
    // Proposal ID to vote on
    bytes32 constant PROPOSAL_ID = 0xf3b5be3a784898de48efdba792837d0f010b1ec3da7533dbf1c5229ed3a9d55e;
    
    // Encrypted vote data
    bytes constant ENCRYPTED_VOTE = hex"a84a6deba3eae1b42aa08610a3dd3f9607b5726fa57e010eb78ab70c1f78421328f47711f04d28a5676781e1e18b87de35";

    function run() external {
        
        // Get voter3 private key from .env
        uint256 voterKey = vm.envUint("VOTER3_PRIVATE_KEY");
        address voter = vm.addr(voterKey);

        vm.startBroadcast(voterKey);

        Governance governance = Governance(GOVERNANCE_PROXY);

        console.log("=== Voting on Proposal ===");
        console.log("Proposal ID:", vm.toString(PROPOSAL_ID));
        console.log("Voter:", voter);
        console.log("Encrypted Vote Length:", ENCRYPTED_VOTE.length);
        console.log("");

        // Check if vote activation has started
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(PROPOSAL_ID);

        console.log("=== Proposal Timeline ===");
        console.log("Proposed at:", timeInfo.proposedTimestamp);
        console.log("Vote activation at:", timeInfo.voteActivationTimestamp);
        console.log("Vote deadline at:", timeInfo.voteDeadlineTimestamp);
        console.log("Proposal deadline at:", timeInfo.proposalDeadlineTimestamp);
        console.log("Current time:", block.timestamp);
        console.log("");

        if (block.timestamp < timeInfo.voteActivationTimestamp) {
            console.log("ERROR: Vote activation has not started yet!");
            console.log("Vote activation at:", timeInfo.voteActivationTimestamp);
            console.log("Current time:", block.timestamp);
            vm.stopBroadcast();
            return;
        }
        
        if (block.timestamp > timeInfo.voteDeadlineTimestamp) {
            console.log("ERROR: Vote deadline has passed!");
            console.log("Vote deadline at:", timeInfo.voteDeadlineTimestamp);
            console.log("Current time:", block.timestamp);
            vm.stopBroadcast();
            return;
        }

        // Create encrypted vote data array
        bytes[] memory encryptedVotes = new bytes[](1);
        encryptedVotes[0] = ENCRYPTED_VOTE;
        
        address[] memory delegators = new address[](1);
        delegators[0] = address(0); // No delegation
        
        uint256[] memory delegatorChainIds = new uint256[](1);
        delegatorChainIds[0] = 0; // No delegation

        // Submit vote
        try governance.vote(PROPOSAL_ID, encryptedVotes, delegators, delegatorChainIds) {
            console.log("Vote submitted successfully!");
            console.log("Voter:", voter);
            console.log("Proposal ID:", vm.toString(PROPOSAL_ID));
        } catch Error(string memory reason) {
            console.log("ERROR: Vote submission failed!");
            console.log("Reason:", reason);
        }

        vm.stopBroadcast();
    }
}
