// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {DeployGovernance} from "../../script/governance/DeployGovernance.s.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {IGovernanceErrors} from "../../src/governance/interfaces/IGovernanceErrors.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {MockERC20} from "../../src/governance/Mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {GovernanceSetup} from "./GovernanceSetup.t.sol";

contract GovernanceVoteTest is GovernanceSetup {

    bytes32 public proposalId;
    bytes public voteEncrypted;

    function setUp() public override {
        super.setUp();
        
        // Create a proposal for testing
        proposalId = _createTestProposal();
        
        // Create test vote data
        voteEncrypted = abi.encode("test vote data");
    }

    function _createTestProposal() internal returns (bytes32) {
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("function()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Test Proposal for Voting",
            description: "This proposal is created for testing vote functionality",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        return governance.propose{value: 0}(params);
    }

    // ========== Basic Vote Tests ==========
    
    function test_vote_Success() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        (address voter, bytes memory storedVote) = governance.getVoteInfo(proposalId, 0);
        assertEq(voter, voter1, "Voter address not recorded correctly");
        assertEq(storedVote, voteEncrypted, "Vote data not recorded correctly");
        
        // Verify vote count was incremented
        assertEq(governance.getVoteCount(proposalId), 1, "Vote count should be 1");
    }

    function test_vote_MultipleVoters() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes memory vote1 = abi.encode("vote1");
        bytes memory vote2 = abi.encode("vote2");
        bytes memory vote3 = abi.encode("vote3");

        // First voter
        vm.prank(voter1);
        governance.vote(proposalId, vote1, address(0), 0);

        // Second voter
        vm.prank(voter2);
        governance.vote(proposalId, vote2, address(0), 0);

        // Third voter
        vm.prank(voter3);
        governance.vote(proposalId, vote3, address(0), 0);

        // Verify all votes were recorded
        (address voter1_, bytes memory storedVote1) = governance.getVoteInfo(proposalId, 0);
        (address voter2_, bytes memory storedVote2) = governance.getVoteInfo(proposalId, 1);
        (address voter3_, bytes memory storedVote3) = governance.getVoteInfo(proposalId, 2);

        assertEq(voter1_, voter1, "First voter not recorded correctly");
        assertEq(voter2_, voter2, "Second voter not recorded correctly");
        assertEq(voter3_, voter3, "Third voter not recorded correctly");

        assertEq(storedVote1, vote1, "First vote not recorded correctly");
        assertEq(storedVote2, vote2, "Second vote not recorded correctly");
        assertEq(storedVote3, vote3, "Third vote not recorded correctly");

        // Verify vote count
        assertEq(governance.getVoteCount(proposalId), 3, "Vote count should be 3");
    }

    // ========== Error Cases Tests ==========
    
    function test_vote_revert_when_ProposalDoesNotExist() public {
        bytes32 nonExistentProposalId = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.ProposalDoesNotExist.selector);
        governance.vote(nonExistentProposalId, voteEncrypted, address(0), 0);
    }

    function test_vote_revert_when_VotingNotActive_BeforeActivation() public {
        // Try to vote before voting period starts
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.VotingNotActive.selector);
        governance.vote(proposalId, voteEncrypted, address(0), 0);
    }

    function test_vote_revert_when_VotingNotActive_AfterDeadline() public {
        // Fast forward past voting deadline
        vm.warp(block.timestamp + voteActivationDelay + voteDuration + 1);

        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.VotingNotActive.selector);
        governance.vote(proposalId, voteEncrypted, address(0), 0);
    }

    function test_vote_revert_when_VotingNotActive_ExactlyAtDeadline() public {
        // Try to vote exactly at deadline (should fail)
        vm.warp(block.timestamp + voteActivationDelay + voteDuration);

        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.VotingNotActive.selector);
        governance.vote(proposalId, voteEncrypted, address(0), 0);
    }

    // ========== Vote Hash Tests ==========
    
    function test_vote_VoteHashUpdated() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes32 initialVoteHash = governance.getVoteHash(proposalId);

        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        bytes32 updatedVoteHash = governance.getVoteHash(proposalId);
        
        // Vote hash should be updated after voting
        assertTrue(updatedVoteHash != initialVoteHash, "Vote hash should be updated");
    }

    function test_vote_VoteHashConsistency() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes memory vote1 = abi.encode("vote1");
        bytes memory vote2 = abi.encode("vote2");

        vm.prank(voter1);
        governance.vote(proposalId, vote1, address(0), 0);

        bytes32 voteHash1 = governance.getVoteHash(proposalId);

        vm.prank(voter2);
        governance.vote(proposalId, vote2, address(0), 0);

        bytes32 voteHash2 = governance.getVoteHash(proposalId);

        // Each vote should update the hash
        assertTrue(voteHash2 != voteHash1, "Vote hash should change with each vote");
    }

    // ========== Vote Timing Tests ==========
    
    function test_vote_AtVoteActivationTimestamp() public {
        // Vote exactly at activation timestamp
        vm.warp(block.timestamp + voteActivationDelay);

        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Should succeed
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed at activation timestamp");
    }

    function test_vote_JustBeforeVoteDeadline() public {
        // Vote just before deadline
        vm.warp(block.timestamp + voteActivationDelay + voteDuration - 1);

        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Should succeed
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed just before deadline");
    }

    // ========== Vote Data Tests ==========
    
    function test_vote_EmptyVoteData() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes memory emptyVote = "";

        vm.prank(voter1);
        governance.vote(proposalId, emptyVote, address(0), 0);

        // Should succeed with empty vote data
        (address voter, bytes memory storedVote) = governance.getVoteInfo(proposalId, 0);
        assertEq(voter, voter1, "Voter should be recorded");
        assertEq(storedVote, emptyVote, "Empty vote should be stored");
    }

    function test_vote_LargeVoteData() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        // Create large vote data
        bytes memory largeVote = new bytes(1000);
        for (uint256 i = 0; i < 1000; i++) {
            largeVote[i] = bytes1(uint8(i % 256));
        }

        vm.prank(voter1);
        governance.vote(proposalId, largeVote, address(0), 0);

        // Should succeed with large vote data
        (address voter, bytes memory storedVote) = governance.getVoteInfo(proposalId, 0);
        assertEq(voter, voter1, "Voter should be recorded");
        assertEq(storedVote, largeVote, "Large vote should be stored correctly");
    }

    // ========== Vote Index Tests ==========
    
    function test_vote_VoteIndexIncrement() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes memory vote1 = abi.encode("vote1");
        bytes memory vote2 = abi.encode("vote2");
        bytes memory vote3 = abi.encode("vote3");

        // First vote should be at index 0
        vm.prank(voter1);
        governance.vote(proposalId, vote1, address(0), 0);

        // Second vote should be at index 1
        vm.prank(voter2);
        governance.vote(proposalId, vote2, address(0), 0);

        // Third vote should be at index 2
        vm.prank(voter3);
        governance.vote(proposalId, vote3, address(0), 0);

        // Verify vote indices
        (address voter1_, bytes memory storedVote1) = governance.getVoteInfo(proposalId, 0);
        (address voter2_, bytes memory storedVote2) = governance.getVoteInfo(proposalId, 1);
        (address voter3_, bytes memory storedVote3) = governance.getVoteInfo(proposalId, 2);

        assertEq(voter1_, voter1, "Vote at index 0 should be from voter1");
        assertEq(voter2_, voter2, "Vote at index 1 should be from voter2");
        assertEq(voter3_, voter3, "Vote at index 2 should be from voter3");

        assertEq(storedVote1, vote1, "Vote data at index 0 should match");
        assertEq(storedVote2, vote2, "Vote data at index 1 should match");
        assertEq(storedVote3, vote3, "Vote data at index 2 should match");
    }

    // ========== Pause State Tests ==========

    function test_vote_WhenPaused() public {
        // Pause the governance contract
        vm.prank(admin);
        governance.pause();

        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        // Vote should succeed even when paused (vote function doesn't have whenNotPaused modifier)
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed even when paused");
    }

    function test_vote_WhenNotPaused() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        // Contract should not be paused initially
        assertFalse(governance.paused(), "Contract should not be paused initially");

        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Should succeed when not paused
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed when not paused");
    }

    // ========== Multiple Votes from Same Voter Tests ==========
    
    function test_vote_MultipleVotesFromSameVoter() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes memory vote1 = abi.encode("first vote");
        bytes memory vote2 = abi.encode("second vote");
        bytes memory vote3 = abi.encode("third vote");

        // Same voter votes multiple times
        vm.prank(voter1);
        governance.vote(proposalId, vote1, address(0), 0);

        vm.prank(voter1);
        governance.vote(proposalId, vote2, address(0), 0);

        vm.prank(voter1);
        governance.vote(proposalId, vote3, address(0), 0);

        // All votes should be recorded
        assertEq(governance.getVoteCount(proposalId), 3, "All votes should be counted");

        // Verify all votes were stored
        (address voter1_, bytes memory storedVote1) = governance.getVoteInfo(proposalId, 0);
        (address voter2_, bytes memory storedVote2) = governance.getVoteInfo(proposalId, 1);
        (address voter3_, bytes memory storedVote3) = governance.getVoteInfo(proposalId, 2);

        assertEq(voter1_, voter1, "First vote should be from voter1");
        assertEq(voter2_, voter1, "Second vote should be from voter1");
        assertEq(voter3_, voter1, "Third vote should be from voter1");

        assertEq(storedVote1, vote1, "First vote data should match");
        assertEq(storedVote2, vote2, "Second vote data should match");
        assertEq(storedVote3, vote3, "Third vote data should match");
    }

    // ========== Vote Hash Calculation Tests ==========
    
    function test_vote_VoteHashCalculation() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes memory vote1 = abi.encode("vote1");
        bytes memory vote2 = abi.encode("vote2");

        // Get initial vote hash
        bytes32 initialHash = governance.getVoteHash(proposalId);

        // First vote
        vm.prank(voter1);
        governance.vote(proposalId, vote1, address(0), 0);

        bytes32 hashAfterVote1 = governance.getVoteHash(proposalId);

        // Second vote
        vm.prank(voter2);
        governance.vote(proposalId, vote2, address(0), 0);

        bytes32 hashAfterVote2 = governance.getVoteHash(proposalId);

        // Each vote should produce a different hash
        assertTrue(initialHash != hashAfterVote1, "Hash should change after first vote");
        assertTrue(hashAfterVote1 != hashAfterVote2, "Hash should change after second vote");
        assertTrue(initialHash != hashAfterVote2, "Final hash should be different from initial");
    }

    // ========== Edge Cases Tests ==========
    
    function test_vote_ZeroAddressVoter() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        // This should work (zero address can vote)
        vm.prank(address(0));
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        (address voter, bytes memory storedVote) = governance.getVoteInfo(proposalId, 0);
        assertEq(voter, address(0), "Zero address voter should be recorded");
        assertEq(storedVote, voteEncrypted, "Vote data should be recorded");
    }

    function test_vote_ContractAddressVoter() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        // Create a contract address
        address contractVoter = address(0x1234567890123456789012345678901234567890);

        vm.prank(contractVoter);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        (address voter, bytes memory storedVote) = governance.getVoteInfo(proposalId, 0);
        assertEq(voter, contractVoter, "Contract address voter should be recorded");
        assertEq(storedVote, voteEncrypted, "Vote data should be recorded");
    }

    // ========== Integration Tests ==========
    
    function test_vote_WithProposalTiming() public {
        // Create a proposal and immediately try to vote (should fail)
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.VotingNotActive.selector);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Fast forward to just before activation (should still fail)
        vm.warp(block.timestamp + voteActivationDelay - 1);
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.VotingNotActive.selector);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Fast forward to activation time (should succeed)
        vm.warp(block.timestamp + 1);
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed at activation time");

        // Fast forward to deadline (should fail)
        vm.warp(block.timestamp + voteDuration);
        vm.prank(voter2);
        vm.expectRevert(IGovernanceErrors.VotingNotActive.selector);
        governance.vote(proposalId, voteEncrypted, address(0), 0);
    }
}
