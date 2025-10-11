// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {DeployGovernance} from "../../script/governance/DeployGovernance.s.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {IGovernanceErrors} from "../../src/governance/interfaces/IGovernanceErrors.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {MockERC20} from "../../src/governance/mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {GovernanceSetup} from "./GovernanceSetup.t.sol";

contract GovernanceEdgeCasesTest is GovernanceSetup {

    // ========== Boundary Value Tests ==========

    function test_ProposeWithLargeValues() public {
        // Test with large but reasonable values
        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory calldatas = new bytes[](3);
        
        for (uint256 i = 0; i < 3; i++) {
            targets[i] = makeAddr(string(abi.encodePacked("target", i)));
            values[i] = 1 ether; // Reasonable large value
            calldatas[i] = abi.encodeWithSignature("setValue(uint256)", i);
        }
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Large Values Proposal",
            description: "A proposal with large values to test boundary conditions",
            depositToken: address(depositToken)
        });
        
        // Should succeed with correct msg.value
        vm.deal(proposer, 10 ether);
        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 3 ether}(params);
        assertTrue(proposalId != bytes32(0), "Proposal should be created");
    }

    function test_ProposeWithZeroValues() public {
        // Test with zero values
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("setValue(uint256)", 0);
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Zero Values Proposal",
            description: "A proposal with zero values",
            depositToken: address(depositToken)
        });
        
        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);
        
        // Verify proposal was created
        (address proposalProposer,,,,,) = governance.getProposalInfo(proposalId);
        assertTrue(proposalProposer != address(0), "Proposal should be created");
    }

    function test_VoteWithMaximumData() public {
        bytes32 testProposalId = _createSimpleProposal();
        
        // Create maximum size vote data
        bytes memory maxVoteData = new bytes(10000); // 10KB of data
        for (uint256 i = 0; i < maxVoteData.length; i++) {
            maxVoteData[i] = bytes1(uint8(i % 256));
        }
        
        _warpToVotingPeriod(testProposalId);
        
        vm.prank(voter1);
        _vote(testProposalId, maxVoteData, address(0), 0);
        
        // Verify vote was recorded
        assertEq(governance.getVoteCount(testProposalId), 1, "Large vote data should be recorded");
    }

    function test_VoteWithEmptyData() public {
        bytes32 testProposalId = _createSimpleProposal();
        
        _warpToVotingPeriod(testProposalId);
        
        vm.prank(voter1);
        _vote(testProposalId, "", address(0), 0);
        
        // Verify vote was recorded
        assertEq(governance.getVoteCount(testProposalId), 1, "Empty vote data should be recorded");
    }

    // ========== Overflow/Underflow Tests ==========

    function test_ProposalNonceOverflow() public {
        // Create multiple proposals from the same proposer
        for (uint256 i = 0; i < 10; i++) {
            bytes32 testProposalId = _createSimpleProposal();
            (address proposalProposer,,,,,) = governance.getProposalInfo(testProposalId);
            assertTrue(proposalProposer != address(0), "Proposal should be created");
        }
        
        // Verify nonce incremented
        assertEq(governance.proposerNonce(proposer), 10, "Nonce should increment properly");
    }

    function test_VoteCountOverflow() public {
        bytes32 testProposalId = _createSimpleProposal();
        
        _warpToVotingPeriod(testProposalId);
        
        // Create many voters and vote
        for (uint256 i = 0; i < 100; i++) {
            address voter = makeAddr(string(abi.encodePacked("voter", i)));
            bytes memory voteData = abi.encode(string(abi.encodePacked("vote", i)));
            
            vm.prank(voter);
            _vote(testProposalId, voteData, address(0), 0);
        }
        
        // Verify all votes were recorded
        assertEq(governance.getVoteCount(testProposalId), 100, "All votes should be recorded");
    }

    // ========== Memory Limit Tests ==========

    function test_LargeProposalArrays() public {
        // Test with large arrays (but not too large to avoid gas issues)
        address[] memory targets = new address[](50);
        uint256[] memory values = new uint256[](50);
        bytes[] memory calldatas = new bytes[](50);
        
        for (uint256 i = 0; i < 50; i++) {
            targets[i] = makeAddr(string(abi.encodePacked("target", i)));
            values[i] = 0;
            calldatas[i] = abi.encodeWithSignature("setValue(uint256)", i);
        }
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Large Arrays Proposal",
            description: "A proposal with large arrays to test memory limits",
            depositToken: address(depositToken)
        });
        
        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);
        
        // Verify proposal was created
        (address proposalProposer,,,,,) = governance.getProposalInfo(proposalId);
        assertTrue(proposalProposer != address(0), "Large proposal should be created");
    }

    // ========== Timing Edge Cases ==========

    function test_VoteAtExactActivationTime() public {
        bytes32 testProposalId = _createSimpleProposal();
        
        // Warp to exact activation time
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(testProposalId);
        vm.warp(timeInfo.voteActivationTimestamp);
        
        vm.prank(voter1);
        _vote(testProposalId, abi.encode("vote"), address(0), 0);
        
        // Verify vote was recorded
        assertEq(governance.getVoteCount(testProposalId), 1, "Vote at exact activation time should work");
    }

    function test_VoteAtExactDeadline() public {
        bytes32 testProposalId = _createSimpleProposal();
        
        // Warp to exact deadline
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(testProposalId);
        vm.warp(timeInfo.voteDeadlineTimestamp);
        
        vm.prank(voter1);
        vm.expectRevert(IGovernanceErrors.Governance__VotingNotActive.selector);
        _vote(testProposalId, abi.encode("vote"), address(0), 0);
    }

    function test_RefundAfterProposalDeadline() public {
        vm.deal(proposer, 1 ether);
        bytes32 testProposalId = _createProposal(makeAddr("target"), 0.1 ether, abi.encodeWithSignature("function()"), "Test", "Test");
        
        _warpPastDeadline(testProposalId);
        
        vm.prank(proposer);
        governance.refund(testProposalId);
    }

    // ========== Invalid Input Tests ==========

    function test_ProposeWithZeroAddressTarget() public {
        address[] memory targets = new address[](1);
        targets[0] = address(0); // Zero address is allowed, only governance itself is not allowed
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("setValue(uint256)", 42);
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Zero Address Target Proposal",
            description: "A proposal with zero address target",
            depositToken: address(depositToken)
        });
        
        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);
        
        // Verify proposal was created (zero address target is allowed)
        (address proposalProposer,,,,,) = governance.getProposalInfo(proposalId);
        assertTrue(proposalProposer != address(0), "Proposal should be created");
    }

    function test_ProposeWithSelfTarget() public {
        address[] memory targets = new address[](1);
        targets[0] = address(governance); // Self target
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("setValue(uint256)", 42);
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Self Target Proposal",
            description: "A proposal targeting itself",
            depositToken: address(depositToken)
        });
        
        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.propose{value: 0}(params);
    }

    // ========== State Transition Tests ==========

    function test_ProposalStateTransitions() public {
        vm.deal(proposer, 1 ether);
        bytes32 testProposalId = _createProposal(makeAddr("target"), 0.5 ether, abi.encodeWithSignature("function()"), "Test", "Test");
        
        // Initial state: proposal exists but no votes
        assertEq(governance.getVoteCount(testProposalId), 0, "Initial vote count should be 0");
        
        // After voting: vote count increases
        _warpToVotingPeriod(testProposalId);
        vm.prank(voter1);
        _vote(testProposalId, abi.encode("vote"), address(0), 0);
        assertEq(governance.getVoteCount(testProposalId), 1, "Vote count should increase after voting");
        
        // After proposal deadline passes without submitResult
        _warpPastDeadline(testProposalId);
        vm.prank(proposer);
        governance.refund(testProposalId);
        
        // Try to refund again (should fail)
        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.Governance__NotRefundableProposal.selector);
        governance.refund(testProposalId);
    }

    // ========== Gas Limit Tests ==========

    function test_GasLimitWithLargeVoteData() public {
        bytes32 testProposalId = _createSimpleProposal();
        
        // Create very large vote data
        bytes memory largeVoteData = new bytes(50000); // 50KB
        for (uint256 i = 0; i < largeVoteData.length; i++) {
            largeVoteData[i] = bytes1(uint8(i % 256));
        }
        
        _warpToVotingPeriod(testProposalId);
        
        // Vote with large data - should work
        vm.prank(voter1);
        _vote(testProposalId, largeVoteData, address(0), 0);
        
        // Verify vote was recorded
        assertEq(governance.getVoteCount(testProposalId), 1, "Large vote data should be recorded");
    }
}
