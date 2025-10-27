// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

/**
 * @notice Vote on test scenarios for testnet testing
 * @dev Allows each voter to cast their vote on the proposal
 */
contract VoteTestScenario is Script {
    // Contract addresses
    address constant GOVERNANCE_PROXY = 0x51De4205a95fC8B5Dc4a616E616945cfB00facfd;

    // Voter addresses will be derived from private keys in .env

    // Vote types
    uint8 constant VOTE_YES = 1;
    uint8 constant VOTE_NO = 2;
    uint8 constant VOTE_ABSTAIN = 3;
    uint8 constant VOTE_NO_WITH_VETO = 4;

    function run() external {
        // Get proposal ID from command line argument
        string memory proposalIdStr = vm.envString("PROPOSAL_ID");
        bytes32 proposalId = vm.parseBytes32(proposalIdStr);

        console.log("=== Testnet Voting ===");
        console.log("Proposal ID:", vm.toString(proposalId));
        console.log("");

        // Vote for each voter based on scenario
        _voteForVoter(proposalId, VOTE_YES, "VOTER1_PRIVATE_KEY", "Voter1 (26%) - YES");
        _voteForVoter(proposalId, VOTE_YES, "VOTER2_PRIVATE_KEY", "Voter2 (19%) - YES");
        _voteForVoter(proposalId, VOTE_NO, "VOTER3_PRIVATE_KEY", "Voter3 (13%) - NO");
        _voteForVoter(proposalId, VOTE_ABSTAIN, "VOTER4_PRIVATE_KEY", "Voter4 (6%) - ABSTAIN");

        console.log("=== Voting Summary ===");
        console.log("Total YES: 45% (Voter1 + Voter2)");
        console.log("Total NO: 13% (Voter3)");
        console.log("Total ABSTAIN: 6% (Voter4)");
        console.log("Expected Result: PASS (45% > 50% threshold)");
    }

    function voteFailScenario() external {
        // Get proposal ID from command line argument
        string memory proposalIdStr = vm.envString("PROPOSAL_ID");
        bytes32 proposalId = vm.parseBytes32(proposalIdStr);

        console.log("=== Testnet Voting (FAIL Scenario) ===");
        console.log("Proposal ID:", vm.toString(proposalId));
        console.log("");

        // Vote for each voter based on fail scenario
        _voteForVoter(proposalId, VOTE_YES, "VOTER1_PRIVATE_KEY", "Voter1 (26%) - YES");
        _voteForVoter(proposalId, VOTE_NO, "VOTER2_PRIVATE_KEY", "Voter2 (19%) - NO");
        _voteForVoter(proposalId, VOTE_NO, "VOTER3_PRIVATE_KEY", "Voter3 (13%) - NO");
        _voteForVoter(proposalId, VOTE_ABSTAIN, "VOTER4_PRIVATE_KEY", "Voter4 (6%) - ABSTAIN");

        console.log("=== Voting Summary ===");
        console.log("Total YES: 26% (Voter1)");
        console.log("Total NO: 32% (Voter2 + Voter3)");
        console.log("Total ABSTAIN: 6% (Voter4)");
        console.log("Expected Result: FAIL (26% < 50% threshold)");
    }

    function _voteForVoter(bytes32 proposalId, uint8 voteType, string memory privateKeyEnv, string memory description)
        internal
    {
        uint256 voterKey = vm.envUint(privateKeyEnv);

        // Derive voter address from private key
        address voter = vm.addr(voterKey);

        vm.startBroadcast(voterKey);

        Governance governance = Governance(GOVERNANCE_PROXY);

        // Check if vote activation has started
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);

        if (block.timestamp < timeInfo.voteActivationTimestamp) {
            console.log("ERROR: Vote activation has not started yet for", description);
            console.log("Vote activation at:", timeInfo.voteActivationTimestamp);
            console.log("Current time:", block.timestamp);
            vm.stopBroadcast();
            return;
        }
        
        if (block.timestamp > timeInfo.voteDeadlineTimestamp) {
            console.log("ERROR: Vote deadline has passed for", description);
            console.log("Vote deadline at:", timeInfo.voteDeadlineTimestamp);
            console.log("Current time:", block.timestamp);
            vm.stopBroadcast();
            return;
        }

        // Create encrypted vote data (simplified for testnet)
        bytes[] memory encryptedVotes = new bytes[](1);
        encryptedVotes[0] = abi.encode(voteType, block.timestamp, voter);
        
        address[] memory delegators = new address[](0);
        uint256[] memory delegatorChainIds = new uint256[](0);

        // Submit vote
        governance.vote(proposalId, encryptedVotes, delegators, delegatorChainIds);

        console.log("Vote submitted:", description);
        console.log("Vote type:", voteType);
        console.log("Voter:", voter);
        console.log("");

        vm.stopBroadcast();
    }
}
