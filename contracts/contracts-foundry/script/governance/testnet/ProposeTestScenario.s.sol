// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

/**
 * @notice Propose test scenarios for testnet testing
 * @dev Creates proposals with short vote activation and long result submission periods
 * 
 * TEST SCENARIOS:
 * 
 * PASS Scenario (VoteTestScenario.run()):
 * - Voter1 (26%): YES
 * - Voter2 (19%): YES  
 * - Voter3 (13%): NO
 * - Voter4 (6%): ABSTAIN
 * - Total YES: 45% (Voter1 + Voter2)
 * - Total NO: 13% (Voter3)
 * - Total ABSTAIN: 6% (Voter4)
 * - Expected Result: PASS (45% > 50% threshold for approval)
 * 
 * FAIL Scenario (VoteTestScenario.voteFailScenario()):
 * - Voter1 (26%): YES
 * - Voter2 (19%): NO
 * - Voter3 (13%): NO
 * - Voter4 (6%): ABSTAIN
 * - Total YES: 26% (Voter1)
 * - Total NO: 32% (Voter2 + Voter3)
 * - Total ABSTAIN: 6% (Voter4)
 * - Expected Result: FAIL (26% < 50% threshold for approval)
 * 
 * QUORUM & THRESHOLDS:
 * - Min Quorum Threshold: 5% of total supply
 * - Proposal Pass/Veto Threshold: 5% of total supply
 * - Total Voter Holdings: ~64% of total supply (well above quorum)
 * 
 * TIMING:
 * - Vote Activation Delay: 10 seconds (set via SetProposalTimingConfig)
 * - Vote Duration: 2.5 minutes
 * - Proposal Duration: 5.5 hours (for enclave result submission)
 */

// forge script script/governance/testnet/ProposeTestScenario.s.sol:ProposeTestScenario --rpc-url $ARBITRUM_SEPOLIA_RPC_URL --broadcast
contract ProposeTestScenario is Script {
    // Contract addresses from deployment
    address constant GOVERNANCE_PROXY = 0x51De4205a95fC8B5Dc4a616E616945cfB00facfd;
    address constant DEPOSIT_TOKEN = 0x293A148f62665f77ed0f18FC20C66A696cc7632C;

    // Proposer address from .env
    address constant PROPOSER = 0x67230E3D54466be136c72dDc322eF1D8b5B0A1c8;

    // Test parameters
    uint256 constant PROPOSAL_DEPOSIT = 1000e18; // 1000 tokens

    function run() external {
        uint256 proposerKey = vm.envUint("PROPOSER_PRIVATE_KEY");

        vm.startBroadcast(proposerKey);

        Governance governance = Governance(GOVERNANCE_PROXY);
        IERC20 depositToken = IERC20(DEPOSIT_TOKEN);
        
        // Check proposer's deposit token balance
        uint256 proposerBalance = depositToken.balanceOf(PROPOSER);
        console.log("Proposer Balance:", proposerBalance);

        if (proposerBalance < PROPOSAL_DEPOSIT) {
            console.log("ERROR: Insufficient deposit token balance!");
            vm.stopBroadcast();
            return;
        }

        // Approve governance to spend deposit tokens
        depositToken.approve(GOVERNANCE_PROXY, PROPOSAL_DEPOSIT);
        console.log("Approved governance to spend deposit tokens");

        // Create test proposal
        console.log("=== Creating Test Proposal ===");
        IGovernanceTypes.ProposeInputParams memory params = _createTestProposalParams("Test Proposal");
        bytes32 proposalId = governance.propose{value: 0}(params);
        console.log("Proposal ID:", vm.toString(proposalId));
        console.log("");

        // Get proposal info from contract
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);
        (address proposer, , , , , ) = governance.getProposalInfo(proposalId);
        
        // Get proposal timing config from governance contract
        (uint256 voteActivationDelay, uint256 voteDuration, uint256 proposalDuration) = governance.getProposalTimingConfig();

        console.log("=== Testnet Proposal Creation ===");
        console.log("Proposer:", proposer);
        console.log("Vote Activation Delay:", voteActivationDelay, "seconds");
        console.log("Vote Duration:", voteDuration, "seconds");
        console.log("Proposal Duration:", proposalDuration, "seconds");
        console.log("");

        console.log("=== Proposal Timeline ===");
        console.log("Proposed at:", timeInfo.proposedTimestamp);
        console.log("Vote activation at:", timeInfo.voteActivationTimestamp);
        console.log("Vote deadline at:", timeInfo.voteDeadlineTimestamp);
        console.log("Proposal deadline at:", timeInfo.proposalDeadlineTimestamp);
        console.log("");

        console.log("=== Next Steps ===");
        console.log("1. Wait for vote activation (", voteActivationDelay, " seconds)");
        console.log("2. Run vote scripts for each voter");
        console.log("3. Wait for vote deadline (", voteDuration, " seconds total)");
        console.log("4. Run result submission script (", proposalDuration, " seconds window)");
        console.log("");
        console.log("=== Environment Variable to Set ===");
        console.log("export PROPOSAL_ID=", vm.toString(proposalId));

        vm.stopBroadcast();
    }

    function _createTestProposalParams(string memory scenario) internal pure returns (IGovernanceTypes.ProposeInputParams memory) {
        // Create a simple test proposal with empty arrays
        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory calldatas = new bytes[](0);
        
        return IGovernanceTypes.ProposeInputParams({
            depositToken: DEPOSIT_TOKEN,
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: string.concat("Testnet ", scenario, " Proposal"),
            description: string.concat("This is a test proposal for ", scenario, " to verify governance functionality on testnet")
        });
    }
}
