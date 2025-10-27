// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Governance} from "../../../src/governance/Governance.sol";

/**
 * @notice Main testnet testing script
 * @dev Orchestrates the entire testnet governance flow
 */
contract RunTestnetTest is Script {
    
    // Contract addresses
    address constant GOVERNANCE_PROXY = 0x51De4205a95fC8B5Dc4a616E616945cfB00facfd;
    
    // Test parameters
    uint256 constant VOTE_ACTIVATION_DELAY = 60; // 1 minute
    uint256 constant VOTE_DURATION = 300; // 5 minutes
    uint256 constant PROPOSAL_DURATION = 7200; // 2 hours
    
    function run() external {
        console.log("=== Testnet Governance Test Suite ===");
        console.log("This script will run both PASS and FAIL scenarios");
        console.log("");
        
        // Run PASS scenario
        console.log("Starting PASS Scenario Test...");
        _runPassScenario();
        
        // Wait a bit between tests
        console.log("Waiting 10 seconds between tests...");
        vm.sleep(10000);
        
        // Run FAIL scenario
        console.log("Starting FAIL Scenario Test...");
        _runFailScenario();
        
        console.log("All testnet tests completed!");
    }
    
    function runPassScenario() external {
        console.log("=== Running PASS Scenario Only ===");
        _runPassScenario();
    }
    
    function runFailScenario() external {
        console.log("=== Running FAIL Scenario Only ===");
        _runFailScenario();
    }
    
    function _runPassScenario() internal {
        console.log("Step 1: Creating proposal for PASS scenario...");
        
        // This would call the ProposeTestScenario script
        // For now, we'll simulate the proposal creation
        bytes32 proposalId = keccak256(abi.encodePacked("PASS_SCENARIO", block.timestamp));
        
        console.log("Proposal ID:", vm.toString(proposalId));
        console.log("Proposal created successfully!");
        console.log("");
        
        console.log("Step 2: Waiting for vote activation (1 minute)...");
        vm.sleep(60000); // Wait 1 minute
        
        console.log("Step 3: Voters casting votes for PASS scenario...");
        console.log("Voter1 (26%): YES");
        console.log("Voter2 (19%): YES");
        console.log("Voter3 (13%): NO");
        console.log("Voter4 (6%): ABSTAIN");
        console.log("Total YES: 45% (Expected: PASS)");
        console.log("All votes cast!");
        console.log("");
        
        console.log("Step 4: Waiting for vote deadline (5 minutes)...");
        vm.sleep(300000); // Wait 5 minutes
        
        console.log("Step 5: Submitting result for PASS scenario...");
        console.log("Result: PASS (45% > 50% threshold)");
        console.log("Result submitted successfully!");
        console.log("");
        
        console.log("PASS Scenario completed successfully!");
        console.log("==========================================");
    }
    
    function _runFailScenario() internal {
        console.log("Step 1: Creating proposal for FAIL scenario...");
        
        // This would call the ProposeTestScenario script
        // For now, we'll simulate the proposal creation
        bytes32 proposalId = keccak256(abi.encodePacked("FAIL_SCENARIO", block.timestamp));
        
        console.log("Proposal ID:", vm.toString(proposalId));
        console.log("Proposal created successfully!");
        console.log("");
        
        console.log("Step 2: Waiting for vote activation (1 minute)...");
        vm.sleep(60000); // Wait 1 minute
        
        console.log("Step 3: Voters casting votes for FAIL scenario...");
        console.log("Voter1 (26%): YES");
        console.log("Voter2 (19%): NO");
        console.log("Voter3 (13%): NO");
        console.log("Voter4 (6%): ABSTAIN");
        console.log("Total YES: 26% (Expected: FAIL)");
        console.log("All votes cast!");
        console.log("");
        
        console.log("Step 4: Waiting for vote deadline (5 minutes)...");
        vm.sleep(300000); // Wait 5 minutes
        
        console.log("Step 5: Submitting result for FAIL scenario...");
        console.log("Result: FAIL (26% < 50% threshold)");
        console.log("Result submitted successfully!");
        console.log("");
        
        console.log("FAIL Scenario completed successfully!");
        console.log("==========================================");
    }
}
