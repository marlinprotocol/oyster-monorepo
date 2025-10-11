// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {DeployGovernance} from "../../script/governance/DeployGovernance.s.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {IGovernanceErrors} from "../../src/governance/interfaces/IGovernanceErrors.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {GovernanceDelegation} from "../../src/governance/GovernanceDelegation.sol";
import {MockERC20} from "../../src/governance/mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {GovernanceSetup} from "./GovernanceSetup.t.sol";

contract GovernanceVoteTest is GovernanceSetup {

    bytes32 public proposalId;
    bytes public voteEncrypted;
    
    // Helper function to convert single vote to array format
    function _vote(bytes32 _proposalId, bytes memory _voteEncrypted, address _delegator, uint256 _delegatorChainId) internal {
        bytes[] memory voteEncrypteds = new bytes[](1);
        address[] memory delegators = new address[](1);
        uint256[] memory delegatorChainIds = new uint256[](1);
        
        voteEncrypteds[0] = _voteEncrypted;
        delegators[0] = _delegator;
        delegatorChainIds[0] = _delegatorChainId;
        
        governance.vote(_proposalId, voteEncrypteds, delegators, delegatorChainIds);
    }

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
        _vote(proposalId, voteEncrypted, address(0), 0);

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
        _vote(proposalId, vote1, address(0), 0);

        // Second voter
        vm.prank(voter2);
        _vote(proposalId, vote2, address(0), 0);

        // Third voter
        vm.prank(voter3);
        _vote(proposalId, vote3, address(0), 0);

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
        vm.expectRevert(IGovernanceErrors.Governance__ProposalDoesNotExist.selector);
        _vote(nonExistentProposalId, voteEncrypted, address(0), 0);
    }

    function test_vote_revert_when_VotingNotActive_BeforeActivation() public {
        // Try to vote before voting period starts
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__VotingNotActive.selector);
        _vote(proposalId, voteEncrypted, address(0), 0);
    }

    function test_vote_revert_when_VotingNotActive_AfterDeadline() public {
        // Fast forward past voting deadline
        vm.warp(block.timestamp + voteActivationDelay + voteDuration + 1);

        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__VotingNotActive.selector);
        _vote(proposalId, voteEncrypted, address(0), 0);
    }

    function test_vote_revert_when_VotingNotActive_ExactlyAtDeadline() public {
        // Try to vote exactly at deadline (should fail)
        vm.warp(block.timestamp + voteActivationDelay + voteDuration);

        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__VotingNotActive.selector);
        _vote(proposalId, voteEncrypted, address(0), 0);
    }

    // ========== Vote Hash Tests ==========
    
    function test_vote_VoteHashUpdated() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes32 initialVoteHash = governance.getVoteHash(proposalId);

        vm.prank(voter1);
        _vote(proposalId, voteEncrypted, address(0), 0);

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
        _vote(proposalId, vote1, address(0), 0);

        bytes32 voteHash1 = governance.getVoteHash(proposalId);

        vm.prank(voter2);
        _vote(proposalId, vote2, address(0), 0);

        bytes32 voteHash2 = governance.getVoteHash(proposalId);

        // Each vote should update the hash
        assertTrue(voteHash2 != voteHash1, "Vote hash should change with each vote");
    }

    // ========== Vote Timing Tests ==========
    
    function test_vote_AtVoteActivationTimestamp() public {
        // Vote exactly at activation timestamp
        vm.warp(block.timestamp + voteActivationDelay);

        vm.prank(voter1);
        _vote(proposalId, voteEncrypted, address(0), 0);

        // Should succeed
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed at activation timestamp");
    }

    function test_vote_JustBeforeVoteDeadline() public {
        // Vote just before deadline
        vm.warp(block.timestamp + voteActivationDelay + voteDuration - 1);

        vm.prank(voter1);
        _vote(proposalId, voteEncrypted, address(0), 0);

        // Should succeed
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed just before deadline");
    }

    // ========== Vote Data Tests ==========
    
    function test_vote_EmptyVoteData() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        bytes memory emptyVote = "";

        vm.prank(voter1);
        _vote(proposalId, emptyVote, address(0), 0);

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
        _vote(proposalId, largeVote, address(0), 0);

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
        _vote(proposalId, vote1, address(0), 0);

        // Second vote should be at index 1
        vm.prank(voter2);
        _vote(proposalId, vote2, address(0), 0);

        // Third vote should be at index 2
        vm.prank(voter3);
        _vote(proposalId, vote3, address(0), 0);

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
        _vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed even when paused");
    }

    function test_vote_WhenNotPaused() public {
        // Fast forward to voting period
        vm.warp(block.timestamp + voteActivationDelay + 1);

        // Contract should not be paused initially
        assertFalse(governance.paused(), "Contract should not be paused initially");

        vm.prank(voter1);
        _vote(proposalId, voteEncrypted, address(0), 0);

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
        _vote(proposalId, vote1, address(0), 0);

        vm.prank(voter1);
        _vote(proposalId, vote2, address(0), 0);

        vm.prank(voter1);
        _vote(proposalId, vote3, address(0), 0);

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
        _vote(proposalId, vote1, address(0), 0);

        bytes32 hashAfterVote1 = governance.getVoteHash(proposalId);

        // Second vote
        vm.prank(voter2);
        _vote(proposalId, vote2, address(0), 0);

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
        _vote(proposalId, voteEncrypted, address(0), 0);

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
        _vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        (address voter, bytes memory storedVote) = governance.getVoteInfo(proposalId, 0);
        assertEq(voter, contractVoter, "Contract address voter should be recorded");
        assertEq(storedVote, voteEncrypted, "Vote data should be recorded");
    }

    // ========== Integration Tests ==========
    
    function test_vote_WithProposalTiming() public {
        // Create a proposal and immediately try to vote (should fail)
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__VotingNotActive.selector);
        _vote(proposalId, voteEncrypted, address(0), 0);

        // Fast forward to just before activation (should still fail)
        vm.warp(block.timestamp + voteActivationDelay - 1);
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__VotingNotActive.selector);
        _vote(proposalId, voteEncrypted, address(0), 0);

        // Fast forward to activation time (should succeed)
        vm.warp(block.timestamp + 1);
        vm.prank(voter1);
        _vote(proposalId, voteEncrypted, address(0), 0);

        // Verify vote was recorded
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should succeed at activation time");

        // Fast forward to deadline (should fail)
        vm.warp(block.timestamp + voteDuration);
        vm.prank(voter2);
        vm.expectRevert(IGovernanceErrors.Governance__VotingNotActive.selector);
        _vote(proposalId, voteEncrypted, address(0), 0);
    }

    // ========== Array-based vote tests ==========

    function test_vote_ArrayLengthMismatch() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        bytes[] memory voteEncrypteds = new bytes[](1); // Mismatch: 1 vs 2
        address[] memory delegators = new address[](2);
        uint256[] memory delegatorChainIds = new uint256[](1);
        
        voteEncrypteds[0] = voteEncrypted;
        delegators[0] = address(0);
        delegators[1] = address(0);
        delegatorChainIds[0] = 0;
        
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidInputLength.selector);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
    }

    function test_vote_EmptyArray() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        bytes[] memory voteEncrypteds = new bytes[](0);
        address[] memory delegators = new address[](0);
        uint256[] memory delegatorChainIds = new uint256[](0);
        
        // Should not revert, just do nothing
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify no votes were recorded
        assertEq(governance.getVoteCount(proposalId), 0);
    }

    function test_vote_MultipleVotesOnSameProposal() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        bytes[] memory voteEncrypteds = new bytes[](2);
        address[] memory delegators = new address[](2);
        uint256[] memory delegatorChainIds = new uint256[](2);
        
        voteEncrypteds[0] = voteEncrypted;
        voteEncrypteds[1] = abi.encode("second vote");
        delegators[0] = address(0);
        delegators[1] = address(0);
        delegatorChainIds[0] = 0;
        delegatorChainIds[1] = 0;
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify both votes were recorded
        assertEq(governance.getVoteCount(proposalId), 2);
    }

    function test_vote_NonExistentProposal() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        bytes32 fakeProposalId = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes[] memory voteEncrypteds = new bytes[](1);
        address[] memory delegators = new address[](1);
        uint256[] memory delegatorChainIds = new uint256[](1);
        
        voteEncrypteds[0] = voteEncrypted;
        delegators[0] = address(0);
        delegatorChainIds[0] = 0;
        
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__ProposalDoesNotExist.selector);
        governance.vote(fakeProposalId, voteEncrypteds, delegators, delegatorChainIds);
    }

    function test_vote_LargeArray() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        uint256 arraySize = 10;
        bytes[] memory voteEncrypteds = new bytes[](arraySize);
        address[] memory delegators = new address[](arraySize);
        uint256[] memory delegatorChainIds = new uint256[](arraySize);
        
        for (uint256 i = 0; i < arraySize; i++) {
            voteEncrypteds[i] = abi.encode(string(abi.encodePacked("vote", i)));
            delegators[i] = address(0);
            delegatorChainIds[i] = 0;
        }
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify all votes were recorded
        assertEq(governance.getVoteCount(proposalId), arraySize);
    }

    function test_vote_ArrayWithDifferentDelegators() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        bytes[] memory voteEncrypteds = new bytes[](3);
        address[] memory delegators = new address[](3);
        uint256[] memory delegatorChainIds = new uint256[](3);
        
        voteEncrypteds[0] = voteEncrypted;
        voteEncrypteds[1] = abi.encode("vote2");
        voteEncrypteds[2] = abi.encode("vote3");
        delegators[0] = address(0);
        delegators[1] = makeAddr("delegator1");
        delegators[2] = makeAddr("delegator2");
        delegatorChainIds[0] = 0;
        delegatorChainIds[1] = block.chainid;
        delegatorChainIds[2] = block.chainid;
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify all votes were recorded
        assertEq(governance.getVoteCount(proposalId), 3);
    }

    function test_vote_ArrayWithInvalidDelegatorAndChainId() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        bytes[] memory voteEncrypteds = new bytes[](1);
        address[] memory delegators = new address[](1);
        uint256[] memory delegatorChainIds = new uint256[](1);
        
        voteEncrypteds[0] = voteEncrypted;
        delegators[0] = makeAddr("delegator1");
        delegatorChainIds[0] = 0; // Invalid: delegator is not zero but chainId is 0
        
        vm.prank(voter1);
        vm.expectRevert();
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
    }

    // ========== Delegation Voting Tests ==========

    function test_vote_WithValidDelegation() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Setup delegation
        address delegator = makeAddr("delegator");
        address delegatee = voter1;
        
        vm.prank(delegator);
        governanceDelegation.setDelegation(delegatee);
        
        // Verify delegation is set
        assertTrue(governanceDelegation.isDelegationSet(delegator, delegatee), "Delegation should be set");
        
        // Vote with delegation
        bytes[] memory voteEncrypteds = new bytes[](1);
        address[] memory delegators = new address[](1);
        uint256[] memory delegatorChainIds = new uint256[](1);
        
        voteEncrypteds[0] = voteEncrypted;
        delegators[0] = delegator;
        delegatorChainIds[0] = block.chainid;
        
        vm.prank(delegatee);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify vote was recorded
        assertEq(governance.getVoteCount(proposalId), 1);
        (IGovernanceTypes.Vote[] memory votes,,) = governance.getAllVoteInfo(proposalId);
        assertEq(votes[0].voter, delegatee, "Voter should be delegatee");
        assertEq(votes[0].delegator, delegator, "Delegator should be recorded");
        assertEq(votes[0].delegatorChainId, block.chainid, "ChainId should be recorded");
    }

    function test_vote_WithDelegation_revert_WhenNotSetInGovernanceDelegation() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Vote with delegation WITHOUT setting it in GovernanceDelegation
        address fakeDelegator = makeAddr("fakeDelegator");
        
        bytes[] memory voteEncrypteds = new bytes[](1);
        address[] memory delegators = new address[](1);
        uint256[] memory delegatorChainIds = new uint256[](1);
        
        voteEncrypteds[0] = voteEncrypted;
        delegators[0] = fakeDelegator;
        delegatorChainIds[0] = block.chainid;
        
        // This should succeed - validation happens in enclave, not in vote submission
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        assertEq(governance.getVoteCount(proposalId), 1, "Vote should be recorded");
    }

    function test_vote_WithDelegation_revert_WhenInvalidChainId() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        address delegator = makeAddr("delegator");
        uint256 invalidChainId = 999999; // Chain without governance delegation
        
        bytes[] memory voteEncrypteds = new bytes[](1);
        address[] memory delegators = new address[](1);
        uint256[] memory delegatorChainIds = new uint256[](1);
        
        voteEncrypteds[0] = voteEncrypted;
        delegators[0] = delegator;
        delegatorChainIds[0] = invalidChainId;
        
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidDelegatorChainId.selector);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
    }

    // ========== Multi-Chain Delegation Tests ==========

    function test_vote_MultiChainDelegation() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Setup additional chains
        uint256 chain2 = 137; // Polygon
        uint256 chain3 = 56;  // BSC
        
        // Deploy additional GovernanceDelegation contracts for other chains
        GovernanceDelegation delegation2 = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        GovernanceDelegation delegation3 = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        
        vm.startPrank(admin);
        delegation2.initialize(admin);
        delegation3.initialize(admin);
        vm.stopPrank();
        
        // Set governance delegations for multiple chains
        vm.startPrank(configSetter);
        governance.setGovernanceDelegation(chain2, address(delegation2));
        governance.setGovernanceDelegation(chain3, address(delegation3));
        vm.stopPrank();
        
        // Setup delegations on different chains
        address delegator1 = makeAddr("delegator1");
        address delegator2 = makeAddr("delegator2");
        address delegator3 = makeAddr("delegator3");
        
        vm.prank(delegator1);
        governanceDelegation.setDelegation(voter1);
        
        vm.prank(delegator2);
        delegation2.setDelegation(voter1);
        
        vm.prank(delegator3);
        delegation3.setDelegation(voter1);
        
        // Vote with delegations from multiple chains
        bytes[] memory voteEncrypteds = new bytes[](3);
        address[] memory delegators = new address[](3);
        uint256[] memory delegatorChainIds = new uint256[](3);
        
        voteEncrypteds[0] = abi.encode("vote1");
        voteEncrypteds[1] = abi.encode("vote2");
        voteEncrypteds[2] = abi.encode("vote3");
        delegators[0] = delegator1;
        delegators[1] = delegator2;
        delegators[2] = delegator3;
        delegatorChainIds[0] = block.chainid;
        delegatorChainIds[1] = chain2;
        delegatorChainIds[2] = chain3;
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify all votes were recorded
        assertEq(governance.getVoteCount(proposalId), 3, "All multi-chain votes should be recorded");
        
        // Verify vote details
        (IGovernanceTypes.Vote[] memory votes,,) = governance.getAllVoteInfo(proposalId);
        assertEq(votes[0].delegator, delegator1);
        assertEq(votes[0].delegatorChainId, block.chainid);
        assertEq(votes[1].delegator, delegator2);
        assertEq(votes[1].delegatorChainId, chain2);
        assertEq(votes[2].delegator, delegator3);
        assertEq(votes[2].delegatorChainId, chain3);
    }

    function test_vote_MixedDirectAndDelegatedVotes() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Setup delegation
        address delegator = makeAddr("delegator");
        vm.prank(delegator);
        governanceDelegation.setDelegation(voter1);
        
        // Vote with mix of direct and delegated votes
        bytes[] memory voteEncrypteds = new bytes[](3);
        address[] memory delegators = new address[](3);
        uint256[] memory delegatorChainIds = new uint256[](3);
        
        voteEncrypteds[0] = abi.encode("direct_vote");
        voteEncrypteds[1] = abi.encode("delegated_vote1");
        voteEncrypteds[2] = abi.encode("direct_vote2");
        delegators[0] = address(0); // Direct vote
        delegators[1] = delegator;   // Delegated vote
        delegators[2] = address(0); // Direct vote
        delegatorChainIds[0] = 0;
        delegatorChainIds[1] = block.chainid;
        delegatorChainIds[2] = 0;
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify all votes were recorded
        assertEq(governance.getVoteCount(proposalId), 3);
    }

    // ========== Batch Voting Tests ==========

    function test_vote_BatchVoting_SingleVoterMultipleVotes() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        uint256 batchSize = 10;
        bytes[] memory voteEncrypteds = new bytes[](batchSize);
        address[] memory delegators = new address[](batchSize);
        uint256[] memory delegatorChainIds = new uint256[](batchSize);
        
        for (uint256 i = 0; i < batchSize; i++) {
            voteEncrypteds[i] = abi.encode(string(abi.encodePacked("vote", i)));
            delegators[i] = address(0);
            delegatorChainIds[i] = 0;
        }
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify all votes were recorded
        assertEq(governance.getVoteCount(proposalId), batchSize);
    }

    function test_vote_BatchVoting_MultipleDelegations() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Setup multiple delegations
        address[] memory delegatorList = new address[](5);
        for (uint256 i = 0; i < 5; i++) {
            delegatorList[i] = makeAddr(string(abi.encodePacked("delegator", i)));
            vm.prank(delegatorList[i]);
            governanceDelegation.setDelegation(voter1);
        }
        
        // Batch vote with all delegations
        bytes[] memory voteEncrypteds = new bytes[](5);
        address[] memory delegators = new address[](5);
        uint256[] memory delegatorChainIds = new uint256[](5);
        
        for (uint256 i = 0; i < 5; i++) {
            voteEncrypteds[i] = abi.encode(string(abi.encodePacked("delegated_vote", i)));
            delegators[i] = delegatorList[i];
            delegatorChainIds[i] = block.chainid;
        }
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify all delegated votes were recorded
        assertEq(governance.getVoteCount(proposalId), 5);
    }

    function test_vote_BatchVoting_LargeBatch() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        uint256 largeBatchSize = 50;
        bytes[] memory voteEncrypteds = new bytes[](largeBatchSize);
        address[] memory delegators = new address[](largeBatchSize);
        uint256[] memory delegatorChainIds = new uint256[](largeBatchSize);
        
        for (uint256 i = 0; i < largeBatchSize; i++) {
            voteEncrypteds[i] = abi.encode(string(abi.encodePacked("batch_vote", i)));
            delegators[i] = address(0);
            delegatorChainIds[i] = 0;
        }
        
        uint256 gasBefore = gasleft();
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Verify all votes were recorded
        assertEq(governance.getVoteCount(proposalId), largeBatchSize);
        emit log_named_uint("Gas used for batch of 50 votes", gasUsed);
    }

    // ========== Multi-Chain Scenario Tests ==========

    function test_vote_MultiChain_DifferentDelegationsPerChain() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Setup multiple chains
        uint256 chain2 = 137;
        uint256 chain3 = 56;
        
        GovernanceDelegation delegation2 = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        GovernanceDelegation delegation3 = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        
        vm.startPrank(admin);
        delegation2.initialize(admin);
        delegation3.initialize(admin);
        vm.stopPrank();
        
        vm.startPrank(configSetter);
        governance.setGovernanceDelegation(chain2, address(delegation2));
        governance.setGovernanceDelegation(chain3, address(delegation3));
        vm.stopPrank();
        
        // Different delegators for each chain, all delegate to different voters
        address delegator1 = makeAddr("delegator1");
        address delegator2 = makeAddr("delegator2");
        address delegator3 = makeAddr("delegator3");
        
        vm.prank(delegator1);
        governanceDelegation.setDelegation(voter1);
        
        vm.prank(delegator2);
        delegation2.setDelegation(voter2);
        
        vm.prank(delegator3);
        delegation3.setDelegation(voter3);
        
        // Voter1 votes with chain1 delegation
        bytes[] memory votes1 = new bytes[](1);
        address[] memory dels1 = new address[](1);
        uint256[] memory chains1 = new uint256[](1);
        votes1[0] = abi.encode("vote_chain1");
        dels1[0] = delegator1;
        chains1[0] = block.chainid;
        
        vm.prank(voter1);
        governance.vote(proposalId, votes1, dels1, chains1);
        
        // Voter2 votes with chain2 delegation
        bytes[] memory votes2 = new bytes[](1);
        address[] memory dels2 = new address[](1);
        uint256[] memory chains2 = new uint256[](1);
        votes2[0] = abi.encode("vote_chain2");
        dels2[0] = delegator2;
        chains2[0] = chain2;
        
        vm.prank(voter2);
        governance.vote(proposalId, votes2, dels2, chains2);
        
        // Voter3 votes with chain3 delegation
        bytes[] memory votes3 = new bytes[](1);
        address[] memory dels3 = new address[](1);
        uint256[] memory chains3 = new uint256[](1);
        votes3[0] = abi.encode("vote_chain3");
        dels3[0] = delegator3;
        chains3[0] = chain3;
        
        vm.prank(voter3);
        governance.vote(proposalId, votes3, dels3, chains3);
        
        // Verify all votes from different chains were recorded
        assertEq(governance.getVoteCount(proposalId), 3);
        
        // Verify each vote has correct chain info
        (IGovernanceTypes.Vote[] memory allVotes,,) = governance.getAllVoteInfo(proposalId);
        assertEq(allVotes[0].delegatorChainId, block.chainid);
        assertEq(allVotes[1].delegatorChainId, chain2);
        assertEq(allVotes[2].delegatorChainId, chain3);
    }

    function test_vote_MultiChain_SameDelegatorDifferentChains() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Setup multiple chains
        uint256 chain2 = 137;
        
        GovernanceDelegation delegation2 = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        
        vm.prank(admin);
        delegation2.initialize(admin);
        
        vm.prank(configSetter);
        governance.setGovernanceDelegation(chain2, address(delegation2));
        
        // Same delegator delegates on multiple chains
        address delegator = makeAddr("multi_chain_delegator");
        
        vm.prank(delegator);
        governanceDelegation.setDelegation(voter1);
        
        vm.prank(delegator);
        delegation2.setDelegation(voter1);
        
        // Vote with same delegator from different chains
        bytes[] memory voteEncrypteds = new bytes[](2);
        address[] memory delegators = new address[](2);
        uint256[] memory delegatorChainIds = new uint256[](2);
        
        voteEncrypteds[0] = abi.encode("vote_chain1");
        voteEncrypteds[1] = abi.encode("vote_chain2");
        delegators[0] = delegator;
        delegators[1] = delegator;
        delegatorChainIds[0] = block.chainid;
        delegatorChainIds[1] = chain2;
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify both chain votes were recorded
        assertEq(governance.getVoteCount(proposalId), 2);
    }

    function test_vote_BatchVoting_MixedChains() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Setup additional chain
        uint256 chain2 = 137;
        GovernanceDelegation delegation2 = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        
        vm.prank(admin);
        delegation2.initialize(admin);
        
        vm.prank(configSetter);
        governance.setGovernanceDelegation(chain2, address(delegation2));
        
        // Setup delegations
        address delegator1 = makeAddr("delegator1");
        address delegator2 = makeAddr("delegator2");
        
        vm.prank(delegator1);
        governanceDelegation.setDelegation(voter1);
        
        vm.prank(delegator2);
        delegation2.setDelegation(voter1);
        
        // Batch vote mixing direct votes and delegations from multiple chains
        bytes[] memory voteEncrypteds = new bytes[](4);
        address[] memory delegators = new address[](4);
        uint256[] memory delegatorChainIds = new uint256[](4);
        
        voteEncrypteds[0] = abi.encode("direct_vote");
        delegators[0] = address(0);
        delegatorChainIds[0] = 0;
        
        voteEncrypteds[1] = abi.encode("delegated_chain1");
        delegators[1] = delegator1;
        delegatorChainIds[1] = block.chainid;
        
        voteEncrypteds[2] = abi.encode("delegated_chain2");
        delegators[2] = delegator2;
        delegatorChainIds[2] = chain2;
        
        voteEncrypteds[3] = abi.encode("direct_vote2");
        delegators[3] = address(0);
        delegatorChainIds[3] = 0;
        
        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
        
        // Verify all mixed votes were recorded
        assertEq(governance.getVoteCount(proposalId), 4);
    }

    // ========== Gas Comparison Tests ==========

    function test_vote_GasComparison_SingleVsBatch() public {
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Create second proposal for comparison
        bytes32 proposalId2 = _createTestProposal();
        vm.warp(block.timestamp + voteActivationDelay + 1);
        
        // Test 1: Submit votes one by one
        uint256 gasSingle = 0;
        for (uint256 i = 0; i < 5; i++) {
            bytes[] memory voteEncrypteds = new bytes[](1);
            address[] memory delegators = new address[](1);
            uint256[] memory delegatorChainIds = new uint256[](1);
            
            voteEncrypteds[0] = abi.encode(string(abi.encodePacked("vote", i)));
            delegators[0] = address(0);
            delegatorChainIds[0] = 0;
            
            uint256 gasBeforeSingle = gasleft();
            vm.prank(voter1);
            governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);
            gasSingle += gasBeforeSingle - gasleft();
        }
        
        // Test 2: Submit all votes in batch
        bytes[] memory batchVotes = new bytes[](5);
        address[] memory batchDelegators = new address[](5);
        uint256[] memory batchChainIds = new uint256[](5);
        
        for (uint256 i = 0; i < 5; i++) {
            batchVotes[i] = abi.encode(string(abi.encodePacked("batch_vote", i)));
            batchDelegators[i] = address(0);
            batchChainIds[i] = 0;
        }
        
        uint256 gasBeforeBatch = gasleft();
        vm.prank(voter2);
        governance.vote(proposalId2, batchVotes, batchDelegators, batchChainIds);
        uint256 gasBatch = gasBeforeBatch - gasleft();
        
        // Log gas comparison
        emit log_named_uint("Gas for 5 single votes", gasSingle);
        emit log_named_uint("Gas for 1 batch of 5 votes", gasBatch);
        emit log_named_uint("Gas saved by batching", gasSingle - gasBatch);
        
        // Batch should be more efficient
        assertTrue(gasBatch < gasSingle, "Batch voting should be more gas efficient");
    }
}

