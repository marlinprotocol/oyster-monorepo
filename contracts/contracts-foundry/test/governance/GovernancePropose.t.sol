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

contract GovernanceProposeTest is GovernanceSetup {

    // ========== Basic Propose Tests ==========
    
    function test_propose_Success() public {
        // Prepare proposal parameters
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("someFunction()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Test Proposal",
            description: "This is a test proposal description",
            depositToken: address(depositToken)
        });

        // Get initial balances
        uint256 initialProposerBalance = depositToken.balanceOf(proposer);
        uint256 initialGovernanceBalance = depositToken.balanceOf(address(governance));
        
        // Submit proposal
        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);

        // Verify proposal was created
        assertTrue(proposalId != bytes32(0), "Proposal ID should not be zero");
        
        // Verify proposer nonce was incremented
        assertEq(governance.proposerNonce(proposer), 1, "Proposer nonce should be incremented");
        
        // Verify tokens were locked
        assertEq(depositToken.balanceOf(address(governance)), initialGovernanceBalance + DEPOSIT_AMOUNT, "Tokens should be locked in governance contract");
        assertEq(depositToken.balanceOf(proposer), initialProposerBalance - DEPOSIT_AMOUNT, "Proposer tokens should be deducted");
    }

    function test_propose_MultipleTargets() public {
        // Prepare proposal with multiple targets
        address[] memory targets = new address[](3);
        targets[0] = makeAddr("target1");
        targets[1] = makeAddr("target2");
        targets[2] = makeAddr("target3");
        
        uint256[] memory values = new uint256[](3);
        values[0] = 0;
        values[1] = 0.1 ether;
        values[2] = 0;
        
        bytes[] memory calldatas = new bytes[](3);
        calldatas[0] = abi.encodeWithSignature("function1()");
        calldatas[1] = abi.encodeWithSignature("function2(uint256)", 123);
        calldatas[2] = abi.encodeWithSignature("function3(string)", "test");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Multi-Target Proposal",
            description: "Proposal with multiple targets and values",
            depositToken: address(depositToken)
        });

        // Fund proposer with tokens and ETH
        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.deal(proposer, 1 ether);
        
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0.1 ether}(params);

        assertTrue(proposalId != bytes32(0), "Proposal ID should not be zero");
    }

    // ========== Input Validation Tests ==========
    
    function test_propose_EmptyTargets() public {
        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory calldatas = new bytes[](0);
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Empty Targets Proposal",
            description: "Proposal with no targets",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);

        assertTrue(proposalId != bytes32(0), "Proposal with empty targets should be valid");
    }

    function test_propose_revert_when_MismatchedArrayLengths() public {
        address[] memory targets = new address[](2);
        targets[0] = makeAddr("target1");
        targets[1] = makeAddr("target2");
        
        uint256[] memory values = new uint256[](1); // Mismatched length
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](2);
        calldatas[0] = abi.encodeWithSignature("function1()");
        calldatas[1] = abi.encodeWithSignature("function2()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Mismatched Arrays",
            description: "Proposal with mismatched array lengths",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.InvalidInputLength.selector);
        governance.propose{value: 0}(params);
    }

    function test_propose_revert_when_EmptyTitle() public {
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
            title: "", // Empty title
            description: "Valid description",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.InvalidTitleLength.selector);
        governance.propose{value: 0}(params);
    }

    function test_propose_revert_when_EmptyDescription() public {
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
            title: "Valid Title",
            description: "", // Empty description
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.InvalidTitleLength.selector);
        governance.propose{value: 0}(params);
    }

    function test_propose_revert_when_InvalidTargetAddress() public {
        address[] memory targets = new address[](1);
        targets[0] = address(governance); // Cannot target governance contract itself
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("function()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Invalid Target",
            description: "Proposal targeting governance contract",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.InvalidAddress.selector);
        governance.propose{value: 0}(params);
    }

    function test_propose_revert_when_InvalidMsgValue() public {
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.1 ether; // Value specified but no ETH sent
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("function()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Invalid Msg Value",
            description: "Proposal with mismatched msg.value",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.InvalidMsgValue.selector);
        governance.propose{value: 0}(params); // No ETH sent
    }

    // ========== Token and Deposit Tests ==========
    
    function test_propose_revert_when_UnsupportedToken() public {
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
            title: "Unsupported Token",
            description: "Proposal with unsupported deposit token",
            depositToken: makeAddr("unsupportedToken") // Token not configured
        });

        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.TokenNotSupported.selector);
        governance.propose{value: 0}(params);
    }

    function test_propose_revert_when_InsufficientTokenBalance() public {
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
            title: "Insufficient Balance",
            description: "Proposal with insufficient token balance",
            depositToken: address(depositToken)
        });

        // Clear proposer's existing balance by transferring to admin
        uint256 proposerBalance = depositToken.balanceOf(proposer);
        if (proposerBalance > 0) {
            vm.prank(proposer);
            depositToken.transfer(admin, proposerBalance);
        }
        
        // Fund proposer with less than required amount
        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT - 1); // Give exactly DEPOSIT_AMOUNT - 1
        
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert("ERC20: transfer amount exceeds balance"); // Should revert due to insufficient balance
        governance.propose{value: 0}(params);
    }

    function test_propose_revert_when_InsufficientAllowance() public {
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
            title: "Insufficient Allowance",
            description: "Proposal with insufficient allowance",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        
        // Approve less than required amount
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT / 2);

        vm.prank(proposer);
        vm.expectRevert(); // Should revert due to insufficient allowance
        governance.propose{value: 0}(params);
    }

    // ========== Duplicate Proposal Tests ==========
    
    function test_propose_DuplicateProposal() public {
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
            title: "Duplicate Proposal",
            description: "This proposal will be submitted twice",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT * 2);
        
        vm.startPrank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT * 2);

        // Submit first proposal
        bytes32 proposalId1 = governance.propose{value: 0}(params);
        assertTrue(proposalId1 != bytes32(0), "First proposal should succeed");

        // Note: Since proposal ID includes nonce, the second proposal will have a different ID
        // and won't be considered a duplicate. This test verifies that proposals with different
        // nonces are allowed even with identical parameters.
        bytes32 proposalId2 = governance.propose{value: 0}(params);
        assertTrue(proposalId2 != bytes32(0), "Second proposal should succeed");
        assertTrue(proposalId1 != proposalId2, "Proposal IDs should be different due to nonce");
        assertEq(governance.proposerNonce(proposer), 2, "Proposer nonce should be 2");
        vm.stopPrank();
    }

    // ========== Proposal ID Generation Tests ==========
    
    function test_propose_UniqueProposalIds() public {
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("function()");
        
        IGovernanceTypes.ProposeInputParams memory params1 = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "First Proposal",
            description: "First proposal description",
            depositToken: address(depositToken)
        });

        IGovernanceTypes.ProposeInputParams memory params2 = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Second Proposal", // Different title
            description: "Second proposal description", // Different description
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT * 2);
        
        vm.startPrank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT * 2);

        bytes32 proposalId1 = governance.propose{value: 0}(params1);
        bytes32 proposalId2 = governance.propose{value: 0}(params2);

        assertTrue(proposalId1 != proposalId2, "Proposal IDs should be unique");
        assertEq(governance.proposerNonce(proposer), 2, "Proposer nonce should be 2");
        vm.stopPrank();
    }

    // ========== Pause State Tests ==========
    
    function test_propose_revert_when_WhenPaused() public {
        // Pause the governance contract
        vm.prank(admin);
        governance.pause();

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
            title: "Paused Proposal",
            description: "Proposal when contract is paused",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert(); // Should revert due to pause
        governance.propose{value: 0}(params);
    }

    // ========== Network Configuration Tests ==========
    
    function test_propose_revert_when_NoSupportedChains() public {
        // Create a new governance instance without network configuration
        Governance newGovernance = Governance(address(new ERC1967Proxy(address(new Governance()), "")));
        
        vm.prank(admin);
        newGovernance.initialize(
            admin,
            configSetter,
            treasury,
            minQuorumThreshold,
            proposalPassVetoThreshold,
            vetoSlashRate,
            voteActivationDelay,
            voteDuration,
            proposalDuration,
            maxRPCUrlsPerChain,
            pcr,
            kmsRootServerPubKey,
            kmsPath
        );

        // Set token lock amount but no network config
        vm.prank(configSetter);
        newGovernance.setTokenLockAmount(address(depositToken), DEPOSIT_AMOUNT);

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
            title: "No Supported Chains",
            description: "Proposal when no chains are configured",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(newGovernance), DEPOSIT_AMOUNT);

        vm.prank(proposer);
        vm.expectRevert(IGovernanceErrors.NoSupportedChainConfigured.selector);
        newGovernance.propose{value: 0}(params);
    }

    // ========== Proposal Timing Tests ==========
    
    function test_propose_TimingConfiguration() public {
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
            title: "Timing Test",
            description: "Test proposal timing configuration",
            depositToken: address(depositToken)
        });

        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.prank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);

        uint256 proposalTime = block.timestamp;
        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);

        // Get proposal timing info
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);

        assertEq(timeInfo.proposedTimestamp, proposalTime, "Proposed timestamp should match");
        assertEq(timeInfo.voteActivationTimestamp, proposalTime + voteActivationDelay, "Vote activation timestamp should be correct");
        assertEq(timeInfo.voteDeadlineTimestamp, proposalTime + voteActivationDelay + voteDuration, "Vote deadline timestamp should be correct");
        assertEq(timeInfo.proposalDeadlineTimestamp, proposalTime + proposalDuration, "Proposal deadline timestamp should be correct");
    }

    // ========== Multiple Proposers Tests ==========
    
    function test_propose_MultipleProposers() public {
        address proposer2 = makeAddr("proposer2");
        vm.deal(proposer2, GAS_FUND_AMOUNT);
        vm.prank(admin);
        depositToken.mint(proposer2, DEPOSIT_AMOUNT);

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
            title: "Multi-Proposer Test",
            description: "Test multiple proposers",
            depositToken: address(depositToken)
        });

        // First proposer
        vm.prank(admin);
        depositToken.mint(proposer, DEPOSIT_AMOUNT);
        vm.startPrank(proposer);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);
        bytes32 proposalId1 = governance.propose{value: 0}(params);
        vm.stopPrank();

        // Second proposer
        vm.startPrank(proposer2);
        depositToken.approve(address(governance), DEPOSIT_AMOUNT);
        bytes32 proposalId2 = governance.propose{value: 0}(params);
        vm.stopPrank();

        assertTrue(proposalId1 != proposalId2, "Proposals from different proposers should have different IDs");
        assertEq(governance.proposerNonce(proposer), 1, "First proposer nonce should be 1");
        assertEq(governance.proposerNonce(proposer2), 1, "Second proposer nonce should be 1");
    }

    // ========== Getter Function Tests ==========
    
    function test_getProposalInfo() public {
        // Create a proposal first
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0.1 ether;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("someFunction()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Test Proposal",
            description: "This is a test proposal description",
            depositToken: address(depositToken)
        });

        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0.1 ether}(params);

        // Test getProposalInfo
        (
            address proposalProposer,
            address[] memory proposalTargets,
            uint256[] memory proposalValues,
            bytes[] memory proposalCalldatas,
            string memory proposalTitle,
            string memory proposalDescription
        ) = governance.getProposalInfo(proposalId);
        
        assertEq(proposalProposer, proposer, "Proposer should match");
        assertEq(proposalTargets.length, 1, "Should have 1 target");
        assertEq(proposalTargets[0], makeAddr("target"), "Target should match");
        assertEq(proposalValues.length, 1, "Should have 1 value");
        assertEq(proposalValues[0], 0.1 ether, "Value should match");
        assertEq(proposalCalldatas.length, 1, "Should have 1 calldata");
        assertEq(proposalCalldatas[0], abi.encodeWithSignature("someFunction()"), "Calldata should match");
        assertEq(proposalTitle, "Test Proposal", "Title should match");
        assertEq(proposalDescription, "This is a test proposal description", "Description should match");
    }

    function test_getAllVoteInfo() public {
        // Create a proposal first
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("someFunction()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Test Proposal",
            description: "This is a test proposal description",
            depositToken: address(depositToken)
        });

        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);

        // Wait for voting to be active
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);
        vm.warp(timeInfo.voteActivationTimestamp + 1);

        // Add some votes
        vm.prank(voter1);
        governance.vote(proposalId, "encrypted_vote_1");
        
        vm.prank(voter2);
        governance.vote(proposalId, "encrypted_vote_2");

        // Test getAllVoteInfo
        (
            IGovernanceTypes.Vote[] memory allVotes,
            uint256 voteCount,
            bytes32 voteHash
        ) = governance.getAllVoteInfo(proposalId);
        
        assertEq(allVotes.length, 2, "Should have 2 votes");
        assertEq(voteCount, 2, "Vote count should be 2");
        assertEq(allVotes[0].voter, voter1, "First voter should match");
        assertEq(allVotes[0].voteEncrypted, "encrypted_vote_1", "First vote should match");
        assertEq(allVotes[1].voter, voter2, "Second voter should match");
        assertEq(allVotes[1].voteEncrypted, "encrypted_vote_2", "Second vote should match");
    }

    function test_getVoteCount_WhenNoVotes() public {
        // Create a proposal first
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("someFunction()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Test Proposal",
            description: "This is a test proposal description",
            depositToken: address(depositToken)
        });

        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);

        // Test getVoteCount when no votes
        uint256 voteCount = governance.getVoteCount(proposalId);
        assertEq(voteCount, 0, "Vote count should be 0 when no votes");
    }

    function test_getVoteInfo_WhenVoteExists() public {
        // Create a proposal first
        address[] memory targets = new address[](1);
        targets[0] = makeAddr("target");
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("someFunction()");
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Test Proposal",
            description: "This is a test proposal description",
            depositToken: address(depositToken)
        });

        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);

        // Wait for voting to be active
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);
        vm.warp(timeInfo.voteActivationTimestamp + 1);

        // Add a vote
        vm.prank(voter1);
        governance.vote(proposalId, "encrypted_vote_1");

        // Test getVoteInfo
        (address voteVoter, bytes memory voteEncrypted) = governance.getVoteInfo(proposalId, 0);
        
        assertEq(voteVoter, voter1, "Voter should match");
        assertEq(voteEncrypted, "encrypted_vote_1", "Vote should match");
    }
}
