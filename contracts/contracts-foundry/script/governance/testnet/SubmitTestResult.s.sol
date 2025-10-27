// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {GovernanceEnclave} from "../../../src/governance/GovernanceEnclave.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

/**
 * @notice Submit test result for testnet testing
 * @dev Simulates enclave result submission with proper signatures
 */
contract SubmitTestResult is Script {
    // Contract addresses
    address constant GOVERNANCE_PROXY = 0x51De4205a95fC8B5Dc4a616E616945cfB00facfd;
    address constant GOVERNANCE_ENCLAVE_PROXY = 0x8Af2Fe40cDf8cD9E0e9F0Ca5E165049769CdC788;

    // Result submitter address from .env
    address constant SUBMITTER = 0x67230E3D54466be136c72dDc322eF1D8b5B0A1c8;

    function run() external {
        uint256 submitterKey = vm.envUint("SUBMITTER_PRIVATE_KEY");

        // Get proposal ID from command line argument
        string memory proposalIdStr = vm.envString("PROPOSAL_ID");
        bytes32 proposalId = vm.parseBytes32(proposalIdStr);

        vm.startBroadcast(submitterKey);

        Governance governance = Governance(GOVERNANCE_PROXY);
        GovernanceEnclave enclave = GovernanceEnclave(GOVERNANCE_ENCLAVE_PROXY);

        console.log("=== Testnet Result Submission ===");
        console.log("Proposal ID:", vm.toString(proposalId));
        console.log("Submitter:", SUBMITTER);
        console.log("");

        // Check proposal status
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);

        console.log("=== Proposal Timeline ===");
        console.log("Proposed at:", timeInfo.proposedTimestamp);
        console.log("Vote activation at:", timeInfo.voteActivationTimestamp);
        console.log("Vote deadline at:", timeInfo.voteDeadlineTimestamp);
        console.log("Proposal deadline at:", timeInfo.proposalDeadlineTimestamp);
        console.log("Current time:", block.timestamp);
        console.log("");
        
        if (block.timestamp < timeInfo.voteDeadlineTimestamp) {
            console.log("ERROR: Vote deadline has not passed yet!");
            console.log("Vote deadline at:", timeInfo.voteDeadlineTimestamp);
            console.log("Current time:", block.timestamp);
            vm.stopBroadcast();
            return;
        }
        
        if (block.timestamp > timeInfo.proposalDeadlineTimestamp) {
            console.log("ERROR: Proposal deadline has passed!");
            console.log("Proposal deadline at:", timeInfo.proposalDeadlineTimestamp);
            console.log("Current time:", block.timestamp);
            vm.stopBroadcast();
            return;
        }

        // Create test result data
        IGovernanceTypes.SubmitResultInputParams memory params = _createTestResultParams(proposalId);

        console.log("=== Result Data ===");
        console.log("KMS Signature length:", params.kmsSig.length);
        console.log("Enclave PubKey length:", params.enclavePubKey.length);
        console.log("Enclave Signature length:", params.enclaveSig.length);
        console.log("Result data length:", params.resultData.length);
        console.log("");

        // Submit result
        try governance.submitResult(params) {
            console.log("Result submitted successfully!");
            console.log("Proposal result has been recorded");
        } catch Error(string memory reason) {
            console.log("ERROR: Result submission failed!");
            console.log("Reason:", reason);
        } catch (bytes memory lowLevelData) {
            console.log("ERROR: Result submission failed with low-level error!");
            console.log("Error data:", vm.toString(lowLevelData));
        }

        vm.stopBroadcast();
    }

    function _createTestResultParams(bytes32 proposalId) internal view returns (IGovernanceTypes.SubmitResultInputParams memory) {
        // For testnet, we'll create mock signatures
        // In real scenario, these would come from the enclave
        
        // Mock KMS signature (64 bytes)
        bytes memory kmsSig = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            kmsSig[i] = bytes1(uint8(i + 1));
        }
        
        // Mock enclave public key (65 bytes)
        bytes memory enclavePubKey = new bytes(65);
        for (uint256 i = 0; i < 65; i++) {
            enclavePubKey[i] = bytes1(uint8(i + 1));
        }
        
        // Mock enclave signature (64 bytes)
        bytes memory enclaveSig = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            enclaveSig[i] = bytes1(uint8(i + 65));
        }
        
        // Create result data (simplified for testnet)
        bytes memory resultData = abi.encode(
            proposalId,
            IGovernanceTypes.VoteDecisionResult({
                yes: 45000000000000000000000, // 45% of total supply
                no: 13000000000000000000000,  // 13% of total supply
                abstain: 6000000000000000000000, // 6% of total supply
                noWithVeto: 0,
                totalVotingPower: 31000000000000000000000 // Total voter holdings
            })
        );
        
        // Mock vote decryption key (32 bytes)
        bytes memory voteDecryptionKey = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            voteDecryptionKey[i] = bytes1(uint8(i + 1));
        }
        
        return IGovernanceTypes.SubmitResultInputParams({
            kmsSig: kmsSig,
            enclavePubKey: enclavePubKey,
            enclaveSig: enclaveSig,
            resultData: resultData,
            voteDecryptionKey: voteDecryptionKey
        });
    }
}
