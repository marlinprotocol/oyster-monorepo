// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ProposalActionsBase is Script {
    
    Governance public governance;
    address public depositTokenAddress;
    address public governanceTokenAddress;

    constructor() {
        // Read deployed addresses from JSON
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, "/address.json");
        string memory json = vm.readFile(filePath);
        
        address governanceProxy = vm.parseJsonAddress(json, ".Governance.proxy");
        governance = Governance(governanceProxy);
        depositTokenAddress = vm.parseJsonAddress(json, ".tokens.deposit");
        governanceTokenAddress = vm.parseJsonAddress(json, ".tokens.governance");
        
        console.log("Loaded Governance proxy:", governanceProxy);
    }
}

// forge script script/governance/setters/ProposalActions.s.sol:ProposeSimple --rpc-url <RPC_URL> --broadcast
contract ProposeSimple is ProposalActionsBase {
    
    // Proposal configuration
    address constant TARGET = 0x0000000000000000000000000000000000000000; // Update this
    uint256 constant VALUE = 0;
    bytes constant CALLDATA = hex""; // Update this
    string constant TITLE = "Test Proposal";
    string constant DESCRIPTION = "This is a test proposal";
    
    function run() external {
        // Prepare proposal params
        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        
        uint256[] memory values = new uint256[](1);
        values[0] = VALUE;
        
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = CALLDATA;
        
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            depositToken: depositTokenAddress,
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: TITLE,
            description: DESCRIPTION
        });
        
        // Approve token if needed
        IERC20 depositToken = IERC20(depositTokenAddress);
        uint256 depositAmount = governance.proposalDepositAmounts(depositTokenAddress);
        
        vm.startBroadcast();
        depositToken.approve(address(governance), depositAmount);
        bytes32 proposalId = governance.propose{value: VALUE}(params);
        vm.stopBroadcast();
        
        console.log("Proposal created:");
        console.log("  Proposal ID:");
        console.logBytes32(proposalId);
        console.log("  Title:", TITLE);
        console.log("  Deposit amount:", depositAmount);
    }
}

// forge script script/governance/setters/ProposalActions.s.sol:VoteOnProposal --rpc-url <RPC_URL> --broadcast
contract VoteOnProposal is ProposalActionsBase {
    
    bytes32 constant PROPOSAL_ID = 0x0000000000000000000000000000000000000000000000000000000000000000; // Update this
    bytes constant VOTE_ENCRYPTED = hex"1234567890abcdef"; // Update this - encrypted vote data
    
    function run() external {
        // Prepare vote arrays
        bytes[] memory voteEncrypteds = new bytes[](1);
        voteEncrypteds[0] = VOTE_ENCRYPTED;
        
        address[] memory delegators = new address[](1);
        delegators[0] = address(0); // No delegation
        
        uint256[] memory delegatorChainIds = new uint256[](1);
        delegatorChainIds[0] = 0;
        
        vm.startBroadcast();
        governance.vote(PROPOSAL_ID, voteEncrypteds, delegators, delegatorChainIds);
        vm.stopBroadcast();
        
        console.log("Vote submitted:");
        console.log("  Proposal ID:");
        console.logBytes32(PROPOSAL_ID);
        console.log("  Voter:", msg.sender);
    }
}

// forge script script/governance/setters/ProposalActions.s.sol:VoteWithDelegation --rpc-url <RPC_URL> --broadcast
contract VoteWithDelegation is ProposalActionsBase {
    
    bytes32 constant PROPOSAL_ID = 0x0000000000000000000000000000000000000000000000000000000000000000; // Update this
    bytes constant VOTE_ENCRYPTED = hex"1234567890abcdef"; // Update this
    address constant DELEGATOR_ADDRESS = 0x0000000000000000000000000000000000000000; // Update this
    uint256 constant DELEGATOR_CHAIN_ID = 421614; // Update this
    
    function run() external {
        // Prepare vote arrays with delegation
        bytes[] memory voteEncrypteds = new bytes[](1);
        voteEncrypteds[0] = VOTE_ENCRYPTED;
        
        address[] memory delegators = new address[](1);
        delegators[0] = DELEGATOR_ADDRESS;
        
        uint256[] memory delegatorChainIds = new uint256[](1);
        delegatorChainIds[0] = DELEGATOR_CHAIN_ID;
        
        vm.startBroadcast();
        governance.vote(PROPOSAL_ID, voteEncrypteds, delegators, delegatorChainIds);
        vm.stopBroadcast();
        
        console.log("Delegated vote submitted:");
        console.log("  Proposal ID:");
        console.logBytes32(PROPOSAL_ID);
        console.log("  Voter (delegatee):", msg.sender);
        console.log("  Delegator:", DELEGATOR_ADDRESS);
        console.log("  Delegator Chain ID:", DELEGATOR_CHAIN_ID);
    }
}

// forge script script/governance/setters/ProposalActions.s.sol:SubmitResult --rpc-url <RPC_URL> --broadcast
contract SubmitResult is ProposalActionsBase {
    
    bytes32 constant PROPOSAL_ID = 0x0000000000000000000000000000000000000000000000000000000000000000; // Update this
    bytes constant KMS_SIG = hex""; // Update with valid signature
    bytes constant ENCLAVE_PUB_KEY = hex""; // Update this
    bytes constant ENCLAVE_SIG = hex""; // Update with valid signature
    bytes constant RESULT_DATA = hex""; // Update with encoded result data
    
    function run() external {
        IGovernanceTypes.SubmitResultInputParams memory params = IGovernanceTypes.SubmitResultInputParams({
            kmsSig: KMS_SIG,
            enclavePubKey: ENCLAVE_PUB_KEY,
            enclaveSig: ENCLAVE_SIG,
            resultData: RESULT_DATA,
            voteDecryptionKey: hex"" // Empty vote decryption key for this example
        });
        
        vm.startBroadcast();
        governance.submitResult(params);
        vm.stopBroadcast();
        
        console.log("Result submitted for proposal:");
        console.logBytes32(PROPOSAL_ID);
    }
}

// forge script script/governance/setters/ProposalActions.s.sol:ExecuteProposal --rpc-url <RPC_URL> --broadcast
contract ExecuteProposal is ProposalActionsBase {
    
    bytes32 constant PROPOSAL_ID = 0x0000000000000000000000000000000000000000000000000000000000000000; // Update this
    
    function run() external {
        vm.startBroadcast();
        governance.execute(PROPOSAL_ID);
        vm.stopBroadcast();
        
        console.log("Proposal executed:");
        console.logBytes32(PROPOSAL_ID);
    }
}

// forge script script/governance/setters/ProposalActions.s.sol:RefundProposal --rpc-url <RPC_URL> --broadcast
contract RefundProposal is ProposalActionsBase {
    
    bytes32 constant PROPOSAL_ID = 0x0000000000000000000000000000000000000000000000000000000000000000; // Update this
    
    function run() external {
        vm.startBroadcast();
        governance.refund(PROPOSAL_ID);
        vm.stopBroadcast();
        
        console.log("Proposal refunded:");
        console.logBytes32(PROPOSAL_ID);
    }
}


