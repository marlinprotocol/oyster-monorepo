// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {GovernanceSetup} from "./GovernanceSetup.t.sol";
import {MockEnclave} from "./mocks/MockEnclave.t.sol";
import {MockTarget} from "./mocks/MockTarget.t.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {IGovernanceErrors} from "../../src/governance/interfaces/IGovernanceErrors.sol";

/// @notice Tests for Governance slash functionality
/// @dev Tests deposit slashing when submitResult is not called and when proposal is vetoed
contract GovernanceSlashTest is GovernanceSetup {
    MockEnclave public mockEnclave;
    MockTarget public mockTarget;

    function setUp() public override {
        super.setUp();
        mockEnclave = new MockEnclave();
        mockTarget = new MockTarget();
    }

    // ========== No SubmitResult Slash Tests ==========

    /// @notice Test when proposer loses all deposit tokens when submitResult is not called
    /// @dev After proposal deadline passes without submitResult, proposer loses all deposit tokens
    function test_slashAllDeposit_WhenNoSubmitResult() public {
        // Create a proposal
        address[] memory targets = new address[](1);
        targets[0] = address(mockTarget);
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.1 ether;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 100);
        
        // Propose the governance action
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        bytes32 proposalId = governance.propose{value: 0.1 ether}(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: targets,
                values: values,
                calldatas: calldatas,
                title: "No SubmitResult Proposal",
                description: "A proposal that will not have submitResult called"
            })
        );
        
        // Wait for proposal deadline to pass without calling submitResult
        vm.warp(governance.getProposalTimeInfo(proposalId).proposalDeadlineTimestamp + 1);
        
        // Try to refund - should succeed and get ETH back, but lose all deposit tokens
        vm.prank(proposer);
        governance.refund(proposalId);
        
        // Check balances - proposer should have lost all deposit tokens
        uint256 finalProposerBalance = depositToken.balanceOf(proposer);
        uint256 finalTreasuryBalance = depositToken.balanceOf(treasury);
        uint256 finalProposerETH = proposer.balance;
        
        // Proposer should have lost the deposit amount (deposit tokens are locked in contract)
        // Initial: 1000 tokens, Lost: 100 tokens (deposit), Refund: 0 tokens
        // Final balance: 1000 - 100 + 0 = 900 tokens
        assertEq(
            finalProposerBalance, 
            900 * 1e18, 
            "Proposer should have lost deposit tokens"
        );
        
        // Treasury should not have received anything (deposit tokens remain locked)
        assertEq(
            finalTreasuryBalance, 
            0, 
            "Treasury should not have received anything"
        );
        
        // Proposer should have received ETH refund
        // Initial: 1 ETH, Used: 0.1 ETH, Refund: 0.1 ETH
        // Final balance: 1 - 0.1 + 0.1 = 1 ETH
        assertEq(
            finalProposerETH, 
            1 ether, 
            "Proposer should have received ETH refund"
        );
    }

    /// @notice Test when proposer gets ETH refund when submitResult is not called
    /// @dev After proposal deadline passes, proposer can call refund to get ETH back
    function test_refundETH_WhenNoSubmitResult() public {
        // Create a proposal with ETH value
        address[] memory targets = new address[](1);
        targets[0] = address(mockTarget);
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.5 ether;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 200);
        

        
        // Propose the governance action
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        bytes32 proposalId = governance.propose{value: 0.5 ether}(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: targets,
                values: values,
                calldatas: calldatas,
                title: "ETH Refund Proposal",
                description: "A proposal to test ETH refund"
            })
        );
        
        // Wait for proposal deadline to pass
        vm.warp(governance.getProposalTimeInfo(proposalId).proposalDeadlineTimestamp + 1);
        
        // Call refund to get ETH back
        vm.prank(proposer);
        governance.refund(proposalId);
        
        // Check balances
        uint256 finalProposerBalance = depositToken.balanceOf(proposer);
        uint256 finalProposerETH = proposer.balance;
        
        // Proposer should have lost deposit tokens but got ETH back
        // Initial: 1000 tokens, Lost: 100 tokens (deposit), Refund: 0 tokens
        // Final balance: 1000 - 100 + 0 = 900 tokens
        assertEq(
            finalProposerBalance, 
            900 * 1e18, 
            "Proposer should have lost deposit tokens"
        );
        
        // Proposer should have received ETH refund
        // Initial: 1 ETH, Used: 0.5 ETH, Refund: 0.5 ETH
        // Final balance: 1 - 0.5 + 0.5 = 1 ETH
        assertEq(
            finalProposerETH, 
            1 ether, 
            "Proposer should have received ETH refund"
        );
    }

    // ========== Veto Slash Tests ==========

    /// @notice Test when proposer gets slashed when proposal is vetoed
    /// @dev When proposal is vetoed, proposer loses vetoSlashRate percentage of deposit
    function test_slashPartialDeposit_WhenVetoed() public {
        // Create a proposal
        address[] memory targets = new address[](1);
        targets[0] = address(mockTarget);
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.2 ether;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 300);
        
        // Propose the governance action
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        bytes32 proposalId = governance.propose{value: 0.2 ether}(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: targets,
                values: values,
                calldatas: calldatas,
                title: "Vetoed Proposal",
                description: "A proposal that will be vetoed"
            })
        );
        
        // Get proposal info for signing
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);
        bytes32 networkHash = governanceEnclave.getNetworkHash();
        bytes32 voteHash = governance.getVoteHash(proposalId);
        
        // Wait for vote deadline to pass
        vm.warp(timeInfo.voteDeadlineTimestamp + 1);
        
        // Create veto vote result (20% yes, 10% no, 10% abstain, 60% noWithVeto)
        // yes (20) < (no + noWithVeto) (70) && no (10) < noWithVeto (60) && noWithVeto (60) > threshold (1% = 10)
        MockEnclave.VotePercentage memory votePercentage = MockEnclave.VotePercentage({
            yes: 0.2 * 1e18,     // 20%
            no: 0.1 * 1e18,      // 10%
            abstain: 0.1 * 1e18, // 10%
            noWithVeto: 0.6 * 1e18 // 60%
        });
        
        // Get signed result from MockEnclave
        (bytes32 imageId,,) = governance.getProposalHashes(proposalId);
        IGovernanceTypes.SubmitResultInputParams memory params = mockEnclave.getResult(
            proposalId,
            imageId,
            votePercentage,
            address(governance),
            timeInfo.proposedTimestamp,
            networkHash,
            governance.contractConfigHash(),
            voteHash
        );
        
        // Submit the result - should result in veto
        vm.prank(admin);
        governance.submitResult(params);
        
        // Check balances after veto
        uint256 finalProposerBalance = depositToken.balanceOf(proposer);
        uint256 finalTreasuryBalance = depositToken.balanceOf(treasury);
        uint256 finalProposerETH = proposer.balance;
        
        // Calculate expected slash amount using actual vetoSlashRate from contract
        uint256 actualVetoSlashRate = governance.vetoSlashRate();
        uint256 expectedSlashAmount = (100 * 1e18 * actualVetoSlashRate) / 1e18; // 100 tokens deposit
        
        // Proposer should have received partial refund
        // Initial: 1000 tokens, Lost: 100 tokens (deposit), Refund: 70 tokens (70% of 100)
        // Final balance: 1000 - 100 + 70 = 970 tokens
        assertEq(
            finalProposerBalance, 
            970 * 1e18, 
            "Proposer should have received partial deposit refund"
        );
        
        // Treasury should have received slashed amount
        assertEq(
            finalTreasuryBalance, 
            expectedSlashAmount, 
            "Treasury should have received slashed amount"
        );
        
        // Proposer should have received ETH refund
        // Initial: 1 ETH, Used: 0.2 ETH, Refund: 0.2 ETH
        // Final balance: 1 - 0.2 + 0.2 = 1 ETH
        assertEq(
            finalProposerETH, 
            1 ether, 
            "Proposer should have received ETH refund"
        );
    }

    /// @notice Test when vetoed proposal has no ETH value
    /// @dev When vetoed proposal has no ETH, only deposit tokens are slashed
    function test_slashPartialDeposit_WhenVetoedNoETH() public {
        // Create a proposal with no ETH value
        address[] memory targets = new address[](1);
        targets[0] = address(mockTarget);
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 400);
        

        
        // Propose the governance action
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        bytes32 proposalId = governance.propose{value: 0}(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: targets,
                values: values,
                calldatas: calldatas,
                title: "Vetoed No ETH Proposal",
                description: "A vetoed proposal with no ETH value"
            })
        );
        
        // Get proposal info for signing
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);
        bytes32 networkHash = governanceEnclave.getNetworkHash();
        bytes32 voteHash = governance.getVoteHash(proposalId);
        
        // Wait for vote deadline to pass
        vm.warp(timeInfo.voteDeadlineTimestamp + 1);
        
        // Create veto vote result
        MockEnclave.VotePercentage memory votePercentage = MockEnclave.VotePercentage({
            yes: 0.15 * 1e18,    // 15%
            no: 0.05 * 1e18,     // 5%
            abstain: 0.1 * 1e18, // 10%
            noWithVeto: 0.7 * 1e18 // 70%
        });
        
        // Get signed result from MockEnclave
        (bytes32 imageId2,,) = governance.getProposalHashes(proposalId);
        IGovernanceTypes.SubmitResultInputParams memory params = mockEnclave.getResult(
            proposalId,
            imageId2,
            votePercentage,
            address(governance),
            timeInfo.proposedTimestamp,
            networkHash,
            governance.contractConfigHash(),
            voteHash
        );
        
        // Submit the result - should result in veto (no ETH to refund, but deposit is slashed)
        vm.prank(admin);
        governance.submitResult(params);
        
        // Check that deposit was slashed but no ETH was refunded
        uint256 finalProposerBalance = depositToken.balanceOf(proposer);
        uint256 finalTreasuryBalance = depositToken.balanceOf(treasury);
        
        // Proposer should have received partial refund (70% of deposit tokens)
        assertEq(
            finalProposerBalance, 
            970 * 1e18, 
            "Proposer should have received partial refund from slashed deposit"
        );
        
        // Treasury should have received slashed portion (30% of deposit tokens)
        assertEq(
            finalTreasuryBalance, 
            30 * 1e18, 
            "Treasury should have received slashed portion of deposit"
        );
    }

    // ========== Edge Cases ==========

    /// @notice Test refund before proposal deadline should fail
    /// @dev Refund should only be possible after proposal deadline has passed
    function test_refundRevertWhen_BeforeDeadline() public {
        // Create a proposal
        address[] memory targets = new address[](1);
        targets[0] = address(mockTarget);
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.1 ether;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 500);
        
        // Propose the governance action
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        bytes32 proposalId = governance.propose{value: 0.1 ether}(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: targets,
                values: values,
                calldatas: calldatas,
                title: "Early Refund Test",
                description: "A proposal to test early refund"
            })
        );
        
        // Try to refund before deadline - should fail
        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.Governance__NotRefundableProposal.selector);
        governance.refund(proposalId);
    }

    /// @notice Test refund after submitResult should fail
    /// @dev Once submitResult is called, refund is no longer possible
    function test_refundRevertWhen_AfterSubmitResult() public {
        // Create a proposal
        address[] memory targets = new address[](1);
        targets[0] = address(mockTarget);
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.1 ether;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 600);
        
        // Propose the governance action
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        bytes32 proposalId = governance.propose{value: 0.1 ether}(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: targets,
                values: values,
                calldatas: calldatas,
                title: "SubmitResult Refund Test",
                description: "A proposal to test refund after submitResult"
            })
        );
        
        // Get proposal info for signing
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);
        bytes32 networkHash = governanceEnclave.getNetworkHash();
        bytes32 voteHash = governance.getVoteHash(proposalId);
        
        // Wait for vote deadline to pass
        vm.warp(timeInfo.voteDeadlineTimestamp + 1);
        
        // Submit a result (any result)
        MockEnclave.VotePercentage memory votePercentage = MockEnclave.VotePercentage({
            yes: 0.7 * 1e18,     // 70%
            no: 0.2 * 1e18,      // 20%
            abstain: 0.05 * 1e18, // 5%
            noWithVeto: 0.05 * 1e18 // 5%
        });
        
        (bytes32 imageId3,,) = governance.getProposalHashes(proposalId);
        IGovernanceTypes.SubmitResultInputParams memory params = mockEnclave.getResult(
            proposalId,
            imageId3,
            votePercentage,
            address(governance),
            timeInfo.proposedTimestamp,
            networkHash,
            governance.contractConfigHash(),
            voteHash
        );
        
        vm.prank(admin);
        governance.submitResult(params);
        
        // Wait for proposal deadline to pass
        vm.warp(timeInfo.proposalDeadlineTimestamp + 1);
        
        // Try to refund after submitResult - should fail
        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.Governance__NotRefundableProposal.selector);
        governance.refund(proposalId);
    }

    /// @notice Test refund with non-existent proposal should fail
    /// @dev Refund should fail for non-existent proposals
    function test_refundRevertWhen_NonExistentProposal() public {
        bytes32 nonExistentProposalId = keccak256("non-existent");
        
        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.Governance__ProposalDoesNotExist.selector);
        governance.refund(nonExistentProposalId);
    }

    /// @notice Test multiple refund calls should fail
    /// @dev Refund should only be possible once per proposal
    function test_refundRevertWhen_AlreadyRefunded() public {
        // Create a proposal
        address[] memory targets = new address[](1);
        targets[0] = address(mockTarget);
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.1 ether;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 700);
        
        // Propose the governance action
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        bytes32 proposalId = governance.propose{value: 0.1 ether}(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: targets,
                values: values,
                calldatas: calldatas,
                title: "Multiple Refund Test",
                description: "A proposal to test multiple refunds"
            })
        );
        
        // Wait for proposal deadline to pass
        vm.warp(governance.getProposalTimeInfo(proposalId).proposalDeadlineTimestamp + 1);
        
        // First refund should succeed
        vm.prank(proposer);
        governance.refund(proposalId);
        
        // Second refund should fail due to NotRefundableProposal
        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.Governance__NotRefundableProposal.selector);
        governance.refund(proposalId);
    }
}
