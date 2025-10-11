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
        newEnclave.initialize(admin, kmsPath, kmsRootServerPubKey, pcr0, pcr1, pcr2, maxRPCUrlsPerChain);
        
        vm.prank(configSetter);
        governance.setGovernanceEnclave(address(newEnclave));
        
        assertEq(governance.governanceEnclave(), address(newEnclave), "governanceEnclave not updated");
    }

    function test_setGovernanceEnclave_revert_when_NonConfigSetter() public {
        address newEnclave = makeAddr("newEnclave");
        
        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
        governance.setGovernanceEnclave(newEnclave);
    }

    function test_setGovernanceEnclave_revert_when_ZeroAddress() public {
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.setGovernanceEnclave(address(0));
    }

    // ========== setGovernanceDelegation Tests ==========
    
    function test_setGovernanceDelegation_Success() public {
        GovernanceDelegation newDelegation = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        vm.prank(admin);
        newDelegation.initialize(admin);
        
        uint256 newChainId = 999;
        
        vm.prank(configSetter);
        governance.setGovernanceDelegation(newChainId, address(newDelegation));
        
        assertEq(governance.governanceDelegations(newChainId), address(newDelegation), "governanceDelegation not set");
    }

    function test_setGovernanceDelegation_revert_when_NonConfigSetter() public {
        uint256 chainId = 999;
        address newDelegation = makeAddr("newDelegation");
        
        vm.prank(admin);
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
        governance.setGovernanceDelegation(chainId, newDelegation);
    }

    function test_setGovernanceDelegation_revert_when_ZeroAddress() public {
        uint256 chainId = 999;
        
        vm.prank(configSetter);
        vm.expectRevert(IGovernanceErrors.Governance__InvalidAddress.selector);
        governance.setGovernanceDelegation(chainId, address(0));
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
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
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
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
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
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
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
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
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
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
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
        vm.expectRevert(IGovernanceErrors.Governance__NotConfigSetterRole.selector);
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

    // ========== setTokenLockAmount Tests ==========
    
    function test_setTokenLockAmount_UpdateExisting() public {
        uint256 newAmount = 200 * 1e18;

        vm.prank(configSetter);
        governance.setTokenLockAmount(address(depositToken), newAmount);

        assertEq(governance.proposalDepositAmounts(address(depositToken)), newAmount, "Token lock amount not updated");
    }

    // ========== setProposalPassVetoThreshold Tests ==========
    
    function test_setProposalPassVetoThreshold_MultipleUpdates() public {
        uint256 threshold1 = 0.1 * 1e18;
        uint256 threshold2 = 0.2 * 1e18;
        uint256 threshold3 = 0.3 * 1e18;

        vm.startPrank(configSetter);
        governance.setProposalPassVetoThreshold(threshold1);
        assertEq(governance.proposalPassVetoThreshold(), threshold1);
        
        governance.setProposalPassVetoThreshold(threshold2);
        assertEq(governance.proposalPassVetoThreshold(), threshold2);
        
        governance.setProposalPassVetoThreshold(threshold3);
        assertEq(governance.proposalPassVetoThreshold(), threshold3);
        vm.stopPrank();
    }

    // ========== setMinQuorumThreshold Tests ==========
    
    function test_setMinQuorumThreshold_MultipleUpdates() public {
        uint256 threshold1 = 0.05 * 1e18;
        uint256 threshold2 = 0.10 * 1e18;

        vm.startPrank(configSetter);
        governance.setMinQuorumThreshold(threshold1);
        assertEq(governance.minQuorumThreshold(), threshold1);
        
        governance.setMinQuorumThreshold(threshold2);
        assertEq(governance.minQuorumThreshold(), threshold2);
        vm.stopPrank();
    }

    // ========== setVetoSlashRate Tests ==========
    
    function test_setVetoSlashRate_MultipleUpdates() public {
        uint256 rate1 = 0.1 * 1e18;
        uint256 rate2 = 0.5 * 1e18;
        uint256 rate3 = 1 * 1e18;

        vm.startPrank(configSetter);
        governance.setVetoSlashRate(rate1);
        assertEq(governance.vetoSlashRate(), rate1);
        
        governance.setVetoSlashRate(rate2);
        assertEq(governance.vetoSlashRate(), rate2);
        
        governance.setVetoSlashRate(rate3);
        assertEq(governance.vetoSlashRate(), rate3);
        vm.stopPrank();
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

