// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";

contract SetGovernanceBase is Script {
    
    Governance public governance;

    constructor() {
        // Read deployed addresses from JSON
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, "/address.json");
        string memory json = vm.readFile(filePath);
        
        address governanceProxy = vm.parseJsonAddress(json, ".Governance.proxy");
        governance = Governance(governanceProxy);
        
        console.log("Loaded Governance proxy:", governanceProxy);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:SetTokenLockAmount --rpc-url <RPC_URL> --broadcast
contract SetTokenLockAmount is SetGovernanceBase {
    
    address constant TOKEN_ADDRESS = 0x293A148f62665f77ed0f18FC20C66A696cc7632C;
    uint256 constant LOCK_AMOUNT = 100 * 1e18;
    
    function run() external {
        vm.startBroadcast();
        governance.setTokenLockAmount(TOKEN_ADDRESS, LOCK_AMOUNT);
        vm.stopBroadcast();
        
        console.log("Token lock amount set:");
        console.log("  Token:", TOKEN_ADDRESS);
        console.log("  Amount:", LOCK_AMOUNT);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:SetProposalTimingConfig --rpc-url <RPC_URL> --broadcast
contract SetProposalTimingConfig is SetGovernanceBase {
    
    uint256 constant VOTE_ACTIVATION_DELAY = 5 minutes;
    uint256 constant VOTE_DURATION = 15 minutes;
    uint256 constant PROPOSAL_DURATION = 30 minutes;
    
    function run() external {
        vm.startBroadcast();
        governance.setProposalTimingConfig(VOTE_ACTIVATION_DELAY, VOTE_DURATION, PROPOSAL_DURATION);
        vm.stopBroadcast();
        
        console.log("Proposal timing config set:");
        console.log("  Vote Activation Delay:", VOTE_ACTIVATION_DELAY);
        console.log("  Vote Duration:", VOTE_DURATION);
        console.log("  Proposal Duration:", PROPOSAL_DURATION);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:SetMinQuorumThreshold --rpc-url <RPC_URL> --broadcast
contract SetMinQuorumThreshold is SetGovernanceBase {
    
    uint256 constant MIN_QUORUM_THRESHOLD = 0.05 * 1e18; // 5%
    
    function run() external {
        vm.startBroadcast();
        governance.setMinQuorumThreshold(MIN_QUORUM_THRESHOLD);
        vm.stopBroadcast();
        
        console.log("Min quorum threshold set:", MIN_QUORUM_THRESHOLD);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:SetProposalPassVetoThreshold --rpc-url <RPC_URL> --broadcast
contract SetProposalPassVetoThreshold is SetGovernanceBase {
    
    uint256 constant PROPOSAL_PASS_VETO_THRESHOLD = 0.05 * 1e18; // 5%
    
    function run() external {
        vm.startBroadcast();
        governance.setProposalPassVetoThreshold(PROPOSAL_PASS_VETO_THRESHOLD);
        vm.stopBroadcast();
        
        console.log("Proposal pass/veto threshold set:", PROPOSAL_PASS_VETO_THRESHOLD);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:SetVetoSlashRate --rpc-url <RPC_URL> --broadcast
contract SetVetoSlashRate is SetGovernanceBase {
    
    uint256 constant VETO_SLASH_RATE = 0.3 * 1e18; // 30%
    
    function run() external {
        vm.startBroadcast();
        governance.setVetoSlashRate(VETO_SLASH_RATE);
        vm.stopBroadcast();
        
        console.log("Veto slash rate set:", VETO_SLASH_RATE);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:SetTreasury --rpc-url <RPC_URL> --broadcast
contract SetTreasury is SetGovernanceBase {
    
    address constant TREASURY_ADDRESS = 0x310E2E738BC3654a221488d665a85C78D92317C1;
    
    function run() external {
        vm.startBroadcast();
        governance.setTreasury(TREASURY_ADDRESS);
        vm.stopBroadcast();
        
        console.log("Treasury set:", TREASURY_ADDRESS);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:AddGovernanceDelegation --rpc-url <RPC_URL> --broadcast
contract AddGovernanceDelegation is SetGovernanceBase {
    
    uint256 constant CHAIN_ID = 11155111; // Ethereum Sepolia
    address constant GOVERNANCE_DELEGATION_ADDRESS = 0x0000000000000000000000000000000000000000; // Update this
    
    function run() external {
        vm.startBroadcast();
        governance.addGovernanceDelegation(CHAIN_ID, GOVERNANCE_DELEGATION_ADDRESS);
        vm.stopBroadcast();
        
        console.log("Governance delegation added:");
        console.log("  Chain ID:", CHAIN_ID);
        console.log("  Delegation:", GOVERNANCE_DELEGATION_ADDRESS);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:RemoveGovernanceDelegation --rpc-url <RPC_URL> --broadcast
contract RemoveGovernanceDelegation is SetGovernanceBase {
    
    uint256 constant DELEGATION_INDEX = 0;
    
    function run() external {
        vm.startBroadcast();
        governance.removeGovernanceDelegation(DELEGATION_INDEX);
        vm.stopBroadcast();
        
        console.log("Governance delegation removed at index:", DELEGATION_INDEX);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:SetGovernanceEnclaveAddress --rpc-url <RPC_URL> --broadcast
contract SetGovernanceEnclaveAddress is SetGovernanceBase {
    
    address constant GOVERNANCE_ENCLAVE_ADDRESS = 0x0000000000000000000000000000000000000000; // Update this
    
    function run() external {
        vm.startBroadcast();
        governance.setGovernanceEnclave(GOVERNANCE_ENCLAVE_ADDRESS);
        vm.stopBroadcast();
        
        console.log("Governance enclave set:", GOVERNANCE_ENCLAVE_ADDRESS);
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:PauseGovernance --rpc-url <RPC_URL> --broadcast
contract PauseGovernance is SetGovernanceBase {
    function run() external {
        vm.startBroadcast();
        governance.pause();
        vm.stopBroadcast();
        
        console.log("Governance paused");
    }
}

// forge script script/governance/setters/SetGovernance.s.sol:UnpauseGovernance --rpc-url <RPC_URL> --broadcast
contract UnpauseGovernance is SetGovernanceBase {
    function run() external {
        vm.startBroadcast();
        governance.unpause();
        vm.stopBroadcast();
        
        console.log("Governance unpaused");
    }
}

