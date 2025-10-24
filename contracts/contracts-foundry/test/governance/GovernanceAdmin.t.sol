// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {IGovernanceErrors} from "../../src/governance/interfaces/IGovernanceErrors.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {GovernanceEnclave} from "../../src/governance/GovernanceEnclave.sol";
import {GovernanceDelegation} from "../../src/governance/GovernanceDelegation.sol";
import {MockERC20} from "../../src/governance/mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {GovernanceSetup} from "./GovernanceSetup.t.sol";

contract GovernanceAdminTest is GovernanceSetup {

    // ========== Initial Configuration Tests ==========
    
    function test_initialConfig() public view {
        // Proposal Timing Config
        (uint256 voteActivationDelay_, uint256 voteDuration_, uint256 proposalDuration_) = governance.proposalTimingConfig();
        assertEq(voteActivationDelay_, voteActivationDelay, "voteActivationDelay not matching");
        assertEq(voteDuration_, voteDuration, "voteDuration not matching");
        assertEq(proposalDuration_, proposalDuration, "proposalDuration not matching");
        
        // Other configs
        assertEq(governance.treasury(), treasury, "treasury not matching");
        assertEq(governance.governanceEnclave(), address(governanceEnclave), "governanceEnclave not matching");
        assertEq(governance.minQuorumThreshold(), minQuorumThreshold, "minQuorumThreshold not matching");
        assertEq(governance.proposalPassVetoThreshold(), proposalPassVetoThreshold, "proposalPassVetoThreshold not matching");
        assertEq(governance.vetoSlashRate(), vetoSlashRate, "vetoSlashRate not matching");
    }

    function test_tokenDepositAmount() public view {
        uint256 depositAmount_ = governance.proposalDepositAmounts(address(depositToken));
        assertEq(depositAmount_, DEPOSIT_AMOUNT, "depositAmount not matching");
    }

    // ========== setGovernanceEnclave Tests ==========
    
    function test_setGovernanceEnclave_Success() public {
        GovernanceEnclave newEnclave = GovernanceEnclave(address(new ERC1967Proxy(address(new GovernanceEnclave()), "")));
        vm.prank(admin);
        newEnclave.initialize(admin, kmsRootServerPubKey, pcr0, pcr1, pcr2, maxRPCUrlsPerChain);
        
        vm.prank(configSetter);
        governance.setGovernanceEnclave(address(newEnclave));
        
        assertEq(governance.governanceEnclave(), address(newEnclave), "governanceEnclave not updated");
    }

    function test_setGovernanceEnclave_revert_when_NonConfigSetter() public {
        address newEnclave = makeAddr("newEnclave");
        
        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.setGovernanceEnclave(newEnclave);
    }

    function test_setGovernanceEnclave_revert_when_ZeroAddress() public {
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.setGovernanceEnclave(address(0));
    }

    // ========== addGovernanceDelegation Tests ==========
    
    function test_addGovernanceDelegation_Success() public {
        GovernanceDelegation newDelegation = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        vm.prank(admin);
        newDelegation.initialize(admin);
        
        uint256 newChainId = 999;
        
        // Check initial state
        assertEq(governance.getDelegationChainIds().length, 1, "Should have 1 delegation initially");
        assertEq(governance.getGovernanceDelegation(newChainId), address(0), "Chain should not be configured");
        
        vm.prank(configSetter);
        governance.addGovernanceDelegation(newChainId, address(newDelegation));
        
        // Verify delegation was added
        assertEq(governance.governanceDelegations(newChainId), address(newDelegation), "governanceDelegation not set");
        assertEq(governance.getDelegationChainIds().length, 2, "Should have 2 delegations");
        assertEq(governance.getGovernanceDelegation(newChainId), address(newDelegation), "Chain should be configured");
    }

    function test_addGovernanceDelegation_revert_when_NonConfigSetter() public {
        uint256 chainId = 999;
        address newDelegation = makeAddr("newDelegation");
        
        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.addGovernanceDelegation(chainId, newDelegation);
    }

    function test_addGovernanceDelegation_revert_when_ZeroAddress() public {
        uint256 chainId = 999;
        
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.addGovernanceDelegation(chainId, address(0));
    }

    function test_addGovernanceDelegation_revert_when_ZeroChainId() public {
        address newDelegation = makeAddr("newDelegation");
        
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.addGovernanceDelegation(0, newDelegation);
    }

    function test_addGovernanceDelegation_revert_when_ChainIdAlreadyExists() public {
        // Try to add the same chain ID that was added in setup
        uint256 existingChainId = block.chainid;
        address newDelegation = makeAddr("newDelegation");
        
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.addGovernanceDelegation(existingChainId, newDelegation);
    }

    // ========== removeGovernanceDelegation Tests ==========
    
    function test_removeGovernanceDelegation_Success() public {
        // Add another delegation first
        uint256 newChainId = 999;
        address newDelegation = makeAddr("newDelegation");
        
        vm.prank(configSetter);
        governance.addGovernanceDelegation(newChainId, newDelegation);
        
        // Verify it was added
        assertEq(governance.getDelegationChainIds().length, 2, "Should have 2 delegations");
        assertEq(governance.getGovernanceDelegation(newChainId), newDelegation, "Chain should be configured");
        
        // Remove it (index 1 since it was added second)
        vm.prank(configSetter);
        governance.removeGovernanceDelegation(1);
        
        // Verify it was removed
        assertEq(governance.getDelegationChainIds().length, 1, "Should have 1 delegation");
        assertEq(governance.getGovernanceDelegation(newChainId), address(0), "Chain should not be configured");
        assertEq(governance.governanceDelegations(newChainId), address(0), "governanceDelegation should be zero");
    }

    function test_removeGovernanceDelegation_SwapAndPop() public {
        // Add two more delegations
        uint256 chainId1 = 999;
        uint256 chainId2 = 888;
        address delegation1 = makeAddr("delegation1");
        address delegation2 = makeAddr("delegation2");
        
        vm.startPrank(configSetter);
        governance.addGovernanceDelegation(chainId1, delegation1);
        governance.addGovernanceDelegation(chainId2, delegation2);
        vm.stopPrank();
        
        // Now we have 3 delegations: [block.chainid, chainId1, chainId2]
        assertEq(governance.getDelegationChainIds().length, 3, "Should have 3 delegations");
        
        // Remove the middle one (index 1)
        vm.prank(configSetter);
        governance.removeGovernanceDelegation(1);
        
        // Verify: should have swapped chainId2 to index 1 and popped
        assertEq(governance.getDelegationChainIds().length, 2, "Should have 2 delegations");
        assertEq(governance.getGovernanceDelegation(chainId1), address(0), "chainId1 should not be configured");
        assertEq(governance.getGovernanceDelegation(chainId2), delegation2, "chainId2 should still be configured");
    }

    function test_removeGovernanceDelegation_revert_when_NonConfigSetter() public {
        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.removeGovernanceDelegation(0);
    }

    function test_removeGovernanceDelegation_revert_when_InvalidIndex() public {
        uint256 currentLength = governance.getDelegationChainIds().length;
        
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.removeGovernanceDelegation(currentLength); // Out of bounds
    }

    // ========== getDelegationChainIds Tests ==========
    
    function test_getDelegationChainIds() public {
        // Initially should have only block.chainid
        uint256[] memory chainIds = governance.getDelegationChainIds();
        assertEq(chainIds.length, 1, "Should have 1 chain ID");
        assertEq(chainIds[0], block.chainid, "Should be block.chainid");
        
        // Add more chains
        uint256 chainId1 = 999;
        uint256 chainId2 = 888;
        
        vm.startPrank(configSetter);
        governance.addGovernanceDelegation(chainId1, makeAddr("delegation1"));
        governance.addGovernanceDelegation(chainId2, makeAddr("delegation2"));
        vm.stopPrank();
        
        // Verify all chains are in the array
        chainIds = governance.getDelegationChainIds();
        assertEq(chainIds.length, 3, "Should have 3 chain IDs");
        assertEq(chainIds[0], block.chainid, "First should be block.chainid");
        assertEq(chainIds[1], chainId1, "Second should be chainId1");
        assertEq(chainIds[2], chainId2, "Third should be chainId2");
    }

    // ========== setTokenLockAmount Tests ==========
    
    function test_setTokenLockAmount_FromConfigSetter() public {
        address newToken = makeAddr("newToken");
        uint256 newAmount = 200 * 1e18;

        vm.prank(configSetter);
        governance.setTokenLockAmount(newToken, newAmount);

        assertEq(governance.proposalDepositAmounts(newToken), newAmount, "Token lock amount not set correctly");
    }

    function test_setTokenLockAmount_revert_when_FromNonConfigSetter() public {
        address newToken = makeAddr("newToken");
        uint256 newAmount = 200 * 1e18;

        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.setTokenLockAmount(newToken, newAmount);
    }

    function test_setTokenLockAmount_revert_when_ZeroAmount() public {
        address newToken = makeAddr("newToken");
        uint256 zeroAmount = 0;

        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.setTokenLockAmount(newToken, zeroAmount);
    }

    // ========== setProposalPassVetoThreshold Tests ==========
    
    function test_setProposalPassVetoThreshold_FromConfigSetter() public {
        uint256 newThreshold = 0.5 * 1e18; // 50%

        vm.prank(configSetter);
        governance.setProposalPassVetoThreshold(newThreshold);

        assertEq(governance.proposalPassVetoThreshold(), newThreshold, "proposalPassVetoThreshold not matching");
    }

    function test_setProposalPassVetoThreshold_revert_when_FromNonConfigSetter() public {
        uint256 newThreshold = 0.5 * 1e18;

        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.setProposalPassVetoThreshold(newThreshold);
    }

    function test_setProposalPassVetoThreshold_revert_when_ZeroValue() public {
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__ZeroProposalPassThreshold.selector);
        governance.setProposalPassVetoThreshold(0);
    }

    // ========== setMinQuorumThreshold Tests ==========
    
    function test_setMinQuorumThreshold_FromConfigSetter() public {
        uint256 newThreshold = 0.1 * 1e18; // 10%

        vm.prank(configSetter);
        governance.setMinQuorumThreshold(newThreshold);

        assertEq(governance.minQuorumThreshold(), newThreshold, "minQuorumThreshold not matching");
    }

    function test_setMinQuorumThreshold_revert_when_FromNonConfigSetter() public {
        uint256 newThreshold = 0.1 * 1e18;

        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.setMinQuorumThreshold(newThreshold);
    }

    function test_setMinQuorumThreshold_revert_when_ZeroValue() public {
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidMinQuorumThreshold.selector);
        governance.setMinQuorumThreshold(0);
    }

    // ========== setVetoSlashRate Tests ==========
    
    function test_setVetoSlashRate_FromConfigSetter() public {
        uint256 newRate = 0.1 * 1e18; // 10%

        vm.prank(configSetter);
        governance.setVetoSlashRate(newRate);

        assertEq(governance.vetoSlashRate(), newRate, "vetoSlashRate not matching");
    }

    function test_setVetoSlashRate_revert_when_FromNonConfigSetter() public {
        uint256 newRate = 0.1 * 1e18;

        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.setVetoSlashRate(newRate);
    }

    function test_setVetoSlashRate_revert_when_ExceedsMaxRate() public {
        uint256 exceedRate = 1.1 * 1e18; // 110%

        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidVetoSlashRate.selector);
        governance.setVetoSlashRate(exceedRate);
    }

    function test_setVetoSlashRate_WhenMaxRate() public {
        uint256 maxRate = 1e18; // 100%

        vm.prank(configSetter);
        governance.setVetoSlashRate(maxRate);

        assertEq(governance.vetoSlashRate(), maxRate, "vetoSlashRate should accept max rate");
    }

    // ========== setTreasury Tests ==========
    
    function test_setTreasury_FromConfigSetter() public {
        address newTreasury = makeAddr("newTreasury");

        vm.prank(configSetter);
        governance.setTreasury(newTreasury);

        assertEq(governance.treasury(), newTreasury, "treasury not matching");
    }

    function test_setTreasury_revert_when_FromNonConfigSetter() public {
        address newTreasury = makeAddr("newTreasury");

        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.setTreasury(newTreasury);
    }

    function test_setTreasury_revert_when_ZeroAddress() public {
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.setTreasury(address(0));
    }

    // ========== setProposalTimingConfig Tests ==========
    
    function test_setProposalTimingConfig_FromConfigSetter() public {
        uint256 newVoteActivationDelay = 10 * 60; // 10 minutes
        uint256 newVoteDuration = 20 * 60; // 20 minutes
        uint256 newProposalDuration = 60 * 60; // 1 hour

        vm.prank(configSetter);
        governance.setProposalTimingConfig(newVoteActivationDelay, newVoteDuration, newProposalDuration);

        (uint256 voteActivationDelay_, uint256 voteDuration_, uint256 proposalDuration_) = governance.proposalTimingConfig();
        assertEq(voteActivationDelay_, newVoteActivationDelay, "voteActivationDelay not matching");
        assertEq(voteDuration_, newVoteDuration, "voteDuration not matching");
        assertEq(proposalDuration_, newProposalDuration, "proposalDuration not matching");
    }

    function test_setProposalTimingConfig_revert_when_FromNonConfigSetter() public {
        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__OnlyConfigSetter.selector);
        governance.setProposalTimingConfig(10 * 60, 20 * 60, 60 * 60);
    }

    function test_setProposalTimingConfig_revert_when_ZeroValues() public {
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__ZeroProposalTimeConfig.selector);
        governance.setProposalTimingConfig(0, 0, 0);
    }

    function test_setProposalTimingConfig_revert_when_InvalidConfig() public {
        // This should fail because voteActivationDelay + voteDuration >= proposalDuration
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidProposalTimeConfig.selector);
        governance.setProposalTimingConfig(30 * 60, 30 * 60, 30 * 60);
    }

    function test_setProposalTimingConfig_WhenPartialUpdate() public {
        // Update only one parameter at a time
        uint256 newVoteActivationDelay = 5 * 60;
        
        vm.prank(configSetter);
        governance.setProposalTimingConfig(newVoteActivationDelay, 0, 0);
        
        (uint256 voteActivationDelay_, uint256 voteDuration_, uint256 proposalDuration_) = governance.proposalTimingConfig();
        assertEq(voteActivationDelay_, newVoteActivationDelay, "voteActivationDelay not updated");
        assertEq(voteDuration_, voteDuration, "voteDuration should remain unchanged");
        assertEq(proposalDuration_, proposalDuration, "proposalDuration should remain unchanged");
    }

    // ========== pause/unpause Tests ==========
    
    function test_pause_FromAdmin() public {
        vm.prank(admin);
        governance.pause();
        
        // Verify contract is paused by trying to propose
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
            title: "Test",
            description: "Test",
            depositToken: address(depositToken)
        });
        
        vm.prank(proposer);
        vm.expectRevert();
        governance.propose{value: 0}(params);
    }

    function test_pause_revert_when_NonAdmin() public {
        vm.prank(configSetter);
        vm.expectRevert();
        governance.pause();
    }

    function test_unpause_FromAdmin() public {
        // First pause
        vm.prank(admin);
        governance.pause();
        
        // Then unpause
        vm.prank(admin);
        governance.unpause();
        
        // Verify contract is unpaused by proposing
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
            title: "Test",
            description: "Test",
            depositToken: address(depositToken)
        });
        
        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: 0}(params);
        assertTrue(proposalId != bytes32(0), "Should be able to propose after unpause");
    }

    function test_unpause_revert_when_NonAdmin() public {
        // First pause
        vm.prank(admin);
        governance.pause();
        
        // Try to unpause from non-admin
        vm.prank(configSetter);
        vm.expectRevert();
        governance.unpause();
    }

    // ========== Role Tests ==========
    
    function test_hasRole_Admin() public view {
        assertTrue(governance.hasRole(governance.DEFAULT_ADMIN_ROLE(), admin), "admin should have DEFAULT_ADMIN_ROLE");
    }

    function test_hasRole_ConfigSetter() public view {
        assertTrue(governance.hasRole(governance.CONFIG_SETTER_ROLE(), configSetter), "configSetter should have CONFIG_SETTER_ROLE");
    }

    function test_supportsInterface() public view {
        // Should support AccessControl interface
        bytes4 accessControlInterfaceId = 0x7965db0b; // IAccessControl interface ID
        assertTrue(governance.supportsInterface(accessControlInterfaceId), "Should support IAccessControl");
    }
}

