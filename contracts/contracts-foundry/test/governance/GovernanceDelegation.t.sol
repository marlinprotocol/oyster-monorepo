// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {GovernanceDelegation} from "../../src/governance/GovernanceDelegation.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract GovernanceDelegationTest is Test {
    GovernanceDelegation public governanceDelegation;

    // Test addresses
    address public admin;
    address public delegator1;
    address public delegator2;
    address public delegatee1;
    address public delegatee2;
    address public user;

    function setUp() public {
        // Initialize test addresses
        admin = makeAddr("admin");
        delegator1 = makeAddr("delegator1");
        delegator2 = makeAddr("delegator2");
        delegatee1 = makeAddr("delegatee1");
        delegatee2 = makeAddr("delegatee2");
        user = makeAddr("user");

        // Deploy and initialize GovernanceDelegation
        GovernanceDelegation implementation = new GovernanceDelegation();
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), "");
        governanceDelegation = GovernanceDelegation(address(proxy));

        // Initialize with admin
        governanceDelegation.initialize(admin);
    }

    //-------------------------------- Helpers start --------------------------------//

    /// @dev Helper function to setup a delegation
    function _setupDelegation(address delegator, address delegatee) internal {
        vm.prank(delegator);
        governanceDelegation.setDelegation(delegatee);
    }

    /// @dev Helper function to verify delegation
    function _verifyDelegation(address delegator, address delegatee) internal view {
        assertEq(governanceDelegation.getDelegator(delegator), delegatee, "Delegatee should match");
        // isDelegationSet reverts if delegator or delegatee is address(0)
        if (delegator != address(0) && delegatee != address(0)) {
            assertTrue(governanceDelegation.isDelegationSet(delegator, delegatee), "Delegation should be set");
        }
    }

    /// @dev Helper function to verify no delegation
    function _verifyNoDelegation(address delegator) internal view {
        assertEq(governanceDelegation.getDelegator(delegator), address(0), "Should have no delegatee");
    }

    //-------------------------------- Helpers end --------------------------------//

    //-------------------------------- Initializer Tests --------------------------------//

    function test_initialize_Success() public view {
        assertTrue(
            governanceDelegation.hasRole(governanceDelegation.DEFAULT_ADMIN_ROLE(), admin), "Admin role should be set"
        );
    }

    //-------------------------------- Setters Tests --------------------------------//

    // ========== Basic Delegation Tests ==========

    function test_setDelegation_Success() public {
        vm.expectEmit(true, true, false, false);
        emit GovernanceDelegation.DelegationSet(delegator1, delegatee1);

        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee1);

        _verifyDelegation(delegator1, delegatee1);
    }

    function test_setDelegation_MultipleDelegators() public {
        // First delegator
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee1);

        // Second delegator
        vm.prank(delegator2);
        governanceDelegation.setDelegation(delegatee2);

        // Verify both delegations
        _verifyDelegation(delegator1, delegatee1);
        _verifyDelegation(delegator2, delegatee2);
    }

    function test_setDelegation_MultipleDelegatorsToSameDelegatee() public {
        // Both delegators delegate to same delegatee
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee1);

        vm.prank(delegator2);
        governanceDelegation.setDelegation(delegatee1);

        // Verify both delegations
        _verifyDelegation(delegator1, delegatee1);
        _verifyDelegation(delegator2, delegatee1);
    }

    // ========== Update Delegation Tests ==========

    function test_setDelegation_UpdateDelegation() public {
        // Set initial delegation
        _setupDelegation(delegator1, delegatee1);
        _verifyDelegation(delegator1, delegatee1);

        // Update delegation to new delegatee
        vm.expectEmit(true, true, false, false);
        emit GovernanceDelegation.DelegationSet(delegator1, delegatee2);

        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee2);

        // Verify updated delegation
        _verifyDelegation(delegator1, delegatee2);
        assertFalse(governanceDelegation.isDelegationSet(delegator1, delegatee1), "Old delegation should not be set");
    }

    function test_setDelegation_UpdateToDifferentDelegatee() public {
        // Set initial delegation
        _setupDelegation(delegator1, delegatee1);
        _verifyDelegation(delegator1, delegatee1);

        // Update delegation to different delegatee
        vm.expectEmit(true, true, false, false);
        emit GovernanceDelegation.DelegationSet(delegator1, delegatee2);

        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee2);

        // Verify delegation updated
        _verifyDelegation(delegator1, delegatee2);
    }

    // ========== Error Cases Tests ==========

    function test_setDelegation_revert_WhenDelegationAlreadySet() public {
        // Set delegation
        _setupDelegation(delegator1, delegatee1);

        // Try to set same delegation again
        vm.prank(delegator1);
        vm.expectRevert(GovernanceDelegation.GovernanceDelegation__DelegationAlreadySet.selector);
        governanceDelegation.setDelegation(delegatee1);
    }

    function test_setDelegation_revert_WhenZeroAddressDelegatee() public {
        vm.prank(delegator1);
        vm.expectRevert(GovernanceDelegation.GovernanceDelegation__InvalidAddress.selector);
        governanceDelegation.setDelegation(address(0));
    }

    //-------------------------------- Getters Tests --------------------------------//

    // ========== getDelegator Tests ==========

    function test_getDelegator_WhenDelegationSet() public {
        _setupDelegation(delegator1, delegatee1);

        address delegatee = governanceDelegation.getDelegator(delegator1);
        assertEq(delegatee, delegatee1, "Should return correct delegatee");
    }

    function test_getDelegator_WhenNoDelegation() public view {
        address delegatee = governanceDelegation.getDelegator(delegator1);
        assertEq(delegatee, address(0), "Should return zero address when no delegation");
    }

    function test_getDelegator_AfterUpdate() public {
        // Set initial delegation
        _setupDelegation(delegator1, delegatee1);

        // Update delegation
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee2);

        // Verify getter returns updated delegatee
        address delegatee = governanceDelegation.getDelegator(delegator1);
        assertEq(delegatee, delegatee2, "Should return updated delegatee");
    }

    // ========== isDelegationSet Tests ==========

    function test_isDelegationSet_WhenDelegationSet() public {
        _setupDelegation(delegator1, delegatee1);

        assertTrue(governanceDelegation.isDelegationSet(delegator1, delegatee1), "Should return true");
        assertFalse(
            governanceDelegation.isDelegationSet(delegator1, delegatee2), "Should return false for different delegatee"
        );
    }

    function test_isDelegationSet_WhenNoDelegation() public view {
        assertFalse(
            governanceDelegation.isDelegationSet(delegator1, delegatee1), "Should return false when no delegation"
        );
    }

    function test_isDelegationSet_AfterUpdate() public {
        // Set initial delegation
        _setupDelegation(delegator1, delegatee1);

        // Update delegation
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee2);

        // Verify old delegation is not set
        assertFalse(governanceDelegation.isDelegationSet(delegator1, delegatee1), "Old delegation should not be set");
        assertTrue(governanceDelegation.isDelegationSet(delegator1, delegatee2), "New delegation should be set");
    }

    function test_isDelegationSet_revert_WhenZeroAddressDelegator() public {
        vm.expectRevert(GovernanceDelegation.GovernanceDelegation__InvalidAddress.selector);
        governanceDelegation.isDelegationSet(address(0), delegatee1);
    }

    function test_isDelegationSet_revert_WhenZeroAddressDelegatee() public {
        vm.expectRevert(GovernanceDelegation.GovernanceDelegation__InvalidAddress.selector);
        governanceDelegation.isDelegationSet(delegator1, address(0));
    }

    function test_isDelegationSet_revert_WhenBothZeroAddress() public {
        vm.expectRevert(GovernanceDelegation.GovernanceDelegation__InvalidAddress.selector);
        governanceDelegation.isDelegationSet(address(0), address(0));
    }

    //-------------------------------- Edge Cases Tests --------------------------------//

    // ========== Self Delegation Tests ==========

    function test_setDelegation_SelfDelegation() public {
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegator1);

        _verifyDelegation(delegator1, delegator1);
    }

    function test_setDelegation_UpdateFromSelfDelegation() public {
        // Self delegate
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegator1);

        // Update to different delegatee
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee1);

        _verifyDelegation(delegator1, delegatee1);
    }

    // ========== Zero Address Tests ==========

    function test_setDelegation_ZeroAddressDelegator() public {
        vm.prank(address(0));
        governanceDelegation.setDelegation(delegatee1);

        _verifyDelegation(address(0), delegatee1);
    }

    // ========== Multiple Updates Tests ==========

    function test_setDelegation_ChainOfUpdates() public {
        address[] memory delegatees = new address[](5);
        delegatees[0] = makeAddr("delegatee_0");
        delegatees[1] = makeAddr("delegatee_1");
        delegatees[2] = makeAddr("delegatee_2");
        delegatees[3] = makeAddr("delegatee_3");
        delegatees[4] = makeAddr("delegatee_4");

        // Chain of delegation updates
        for (uint256 i = 0; i < delegatees.length; i++) {
            vm.prank(delegator1);
            governanceDelegation.setDelegation(delegatees[i]);

            _verifyDelegation(delegator1, delegatees[i]);
        }

        // Verify only last delegation is set
        for (uint256 i = 0; i < delegatees.length - 1; i++) {
            assertFalse(
                governanceDelegation.isDelegationSet(delegator1, delegatees[i]),
                "Previous delegations should not be set"
            );
        }
    }

    // ========== Event Tests ==========

    function test_setDelegation_EmitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit GovernanceDelegation.DelegationSet(delegator1, delegatee1);

        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee1);
    }

    function test_setDelegation_EmitsEventOnUpdate() public {
        // Set initial delegation
        _setupDelegation(delegator1, delegatee1);

        // Update and expect event
        vm.expectEmit(true, true, false, false);
        emit GovernanceDelegation.DelegationSet(delegator1, delegatee2);

        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee2);
    }

    // ========== Integration Tests ==========

    function test_integration_MultipleDelegatorsComplexScenario() public {
        address delegatee3 = makeAddr("delegatee3");

        // Delegator1 delegates to delegatee1
        _setupDelegation(delegator1, delegatee1);

        // Delegator2 delegates to delegatee2
        _setupDelegation(delegator2, delegatee2);

        // Verify both
        _verifyDelegation(delegator1, delegatee1);
        _verifyDelegation(delegator2, delegatee2);

        // Delegator1 updates to delegatee2
        vm.prank(delegator1);
        governanceDelegation.setDelegation(delegatee2);

        // Both now delegate to delegatee2
        _verifyDelegation(delegator1, delegatee2);
        _verifyDelegation(delegator2, delegatee2);

        // Delegator2 updates to delegatee3
        vm.prank(delegator2);
        governanceDelegation.setDelegation(delegatee3);

        // Verify final state
        _verifyDelegation(delegator1, delegatee2);
        _verifyDelegation(delegator2, delegatee3);
    }

    function test_integration_CircularDelegation() public {
        // Create circular delegation pattern
        address delegatorA = makeAddr("delegatorA");
        address delegatorB = makeAddr("delegatorB");
        address delegatorC = makeAddr("delegatorC");

        // A delegates to B
        vm.prank(delegatorA);
        governanceDelegation.setDelegation(delegatorB);

        // B delegates to C
        vm.prank(delegatorB);
        governanceDelegation.setDelegation(delegatorC);

        // C delegates to A (circular)
        vm.prank(delegatorC);
        governanceDelegation.setDelegation(delegatorA);

        // Verify circular delegation is set
        _verifyDelegation(delegatorA, delegatorB);
        _verifyDelegation(delegatorB, delegatorC);
        _verifyDelegation(delegatorC, delegatorA);
    }

    // ========== Fuzz Tests ==========

    function testFuzz_setDelegation_Success(address delegator, address delegatee) public {
        // delegatee cannot be address(0)
        vm.assume(delegatee != address(0));

        vm.prank(delegator);
        governanceDelegation.setDelegation(delegatee);

        _verifyDelegation(delegator, delegatee);
    }

    function testFuzz_setDelegation_Update(address delegator, address firstDelegatee, address secondDelegatee) public {
        vm.assume(delegator != address(0)); // delegator cannot be address(0)
        vm.assume(firstDelegatee != secondDelegatee); // Must be different to avoid revert
        vm.assume(firstDelegatee != address(0)); // delegatee cannot be address(0)
        vm.assume(secondDelegatee != address(0)); // delegatee cannot be address(0)

        vm.prank(delegator);
        governanceDelegation.setDelegation(firstDelegatee);

        vm.prank(delegator);
        governanceDelegation.setDelegation(secondDelegatee);

        _verifyDelegation(delegator, secondDelegatee);
        assertFalse(governanceDelegation.isDelegationSet(delegator, firstDelegatee), "Old delegation should not be set");
    }

    function testFuzz_getDelegator(address delegator, address delegatee) public {
        // delegatee cannot be address(0)
        vm.assume(delegatee != address(0));

        vm.prank(delegator);
        governanceDelegation.setDelegation(delegatee);

        address result = governanceDelegation.getDelegator(delegator);
        assertEq(result, delegatee, "Should return correct delegatee");
    }

    function testFuzz_isDelegationSet(address delegator, address delegatee) public {
        // isDelegationSet reverts if delegator or delegatee is address(0)
        vm.assume(delegator != address(0) && delegatee != address(0));

        vm.prank(delegator);
        governanceDelegation.setDelegation(delegatee);

        assertTrue(governanceDelegation.isDelegationSet(delegator, delegatee), "Should return true");
    }
}
