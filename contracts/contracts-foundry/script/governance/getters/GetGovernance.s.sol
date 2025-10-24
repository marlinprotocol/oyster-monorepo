// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";

contract GetGovernanceBase is Script {
    
    Governance public governance;

    constructor() {
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, "/address.json");
        string memory json = vm.readFile(filePath);
        
        address governanceProxy = vm.parseJsonAddress(json, ".Governance.proxy");
        governance = Governance(governanceProxy);
        
        console.log("Loaded Governance proxy:", governanceProxy);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetProposalDepositAmount --rpc-url <RPC_URL> -vvv
contract GetProposalDepositAmount is GetGovernanceBase {
    
    address constant TOKEN_ADDRESS = 0x293A148f62665f77ed0f18FC20C66A696cc7632C;
    
    function run() external view {
        uint256 amount = governance.proposalDepositAmounts(TOKEN_ADDRESS);
        console.log("Proposal deposit amount for token:", TOKEN_ADDRESS);
        console.log("  Amount:", amount);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetProposalTimingConfig --rpc-url <RPC_URL> -vvv
contract GetProposalTimingConfig is GetGovernanceBase {
    function run() external view {
        (uint256 voteActivationDelay, uint256 voteDuration, uint256 proposalDuration) = governance.proposalTimingConfig();
        console.log("Proposal timing config:");
        console.log("  Vote Activation Delay:", voteActivationDelay);
        console.log("  Vote Duration:", voteDuration);
        console.log("  Proposal Duration:", proposalDuration);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetMinQuorumThreshold --rpc-url <RPC_URL> -vvv
contract GetMinQuorumThreshold is GetGovernanceBase {
    function run() external view {
        uint256 threshold = governance.minQuorumThreshold();
        console.log("Min quorum threshold:", threshold);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetProposalPassVetoThreshold --rpc-url <RPC_URL> -vvv
contract GetProposalPassVetoThreshold is GetGovernanceBase {
    function run() external view {
        uint256 threshold = governance.proposalPassVetoThreshold();
        console.log("Proposal pass/veto threshold:", threshold);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetVetoSlashRate --rpc-url <RPC_URL> -vvv
contract GetVetoSlashRate is GetGovernanceBase {
    function run() external view {
        uint256 rate = governance.vetoSlashRate();
        console.log("Veto slash rate:", rate);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetTreasury --rpc-url <RPC_URL> -vvv
contract GetTreasury is GetGovernanceBase {
    function run() external view {
        address treasury = governance.treasury();
        console.log("Treasury address:", treasury);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetGovernanceEnclaveAddress --rpc-url <RPC_URL> -vvv
contract GetGovernanceEnclaveAddress is GetGovernanceBase {
    function run() external view {
        address governanceEnclave = governance.governanceEnclave();
        console.log("Governance enclave address:", governanceEnclave);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetDelegationChainIds --rpc-url <RPC_URL> -vvv
contract GetDelegationChainIds is GetGovernanceBase {
    function run() external view {
        uint256[] memory chainIds = governance.getDelegationChainIds();
        console.log("Delegation chain IDs count:", chainIds.length);
        for (uint256 i = 0; i < chainIds.length; i++) {
            console.log("  Chain ID:", chainIds[i]);
            console.log("    Delegation:", governance.getGovernanceDelegation(chainIds[i]));
        }
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetGovernanceDelegation --rpc-url <RPC_URL> -vvv
contract GetGovernanceDelegation is GetGovernanceBase {
    
    uint256 constant CHAIN_ID = 11155111;
    
    function run() external view {
        address delegation = governance.getGovernanceDelegation(CHAIN_ID);
        console.log("Governance delegation for chain:", CHAIN_ID);
        console.log("  Delegation:", delegation);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetContractConfigHash --rpc-url <RPC_URL> -vvv
contract GetContractConfigHash is GetGovernanceBase {
    function run() external view {
        bytes32 configHash = governance.contractConfigHash();
        console.log("Contract config hash:");
        console.logBytes32(configHash);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetProposalState --rpc-url <RPC_URL> -vvv
contract GetProposalState is GetGovernanceBase {
    
    bytes32 constant PROPOSAL_ID = 0x0000000000000000000000000000000000000000000000000000000000000000;
    
    function run() external view {
        (
            Governance.VoteOutcome voteOutcome,
            bool executed,
            bool inExecutionQueue,
            bytes32 imageId,
            bytes32 networkHash
        ) = governance.getProposalState(PROPOSAL_ID);
        
        console.log("Proposal state for:");
        console.logBytes32(PROPOSAL_ID);
        console.log("  Vote outcome:", uint8(voteOutcome));
        console.log("  Executed:", executed);
        console.log("  In execution queue:", inExecutionQueue);
        console.log("  Image ID:");
        console.logBytes32(imageId);
        console.log("  Network hash:");
        console.logBytes32(networkHash);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetVoteOutcome --rpc-url <RPC_URL> -vvv
contract GetVoteOutcome is GetGovernanceBase {
    
    bytes32 constant PROPOSAL_ID = 0x0000000000000000000000000000000000000000000000000000000000000000;
    
    function run() external view {
        uint8 outcome = uint8(governance.getVoteOutcome(PROPOSAL_ID));
        console.log("Vote outcome for:");
        console.logBytes32(PROPOSAL_ID);
        console.log("  Outcome:", outcome);
    }
}

// forge script script/governance/getters/GetGovernance.s.sol:GetPaused --rpc-url <RPC_URL> -vvv
contract GetPaused is GetGovernanceBase {
    function run() external view {
        bool isPaused = governance.paused();
        console.log("Governance paused:", isPaused);
    }
}

