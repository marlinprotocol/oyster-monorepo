// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {GovernanceAddresses} from "../GovernanceAddresses.s.sol";

contract ProposalActionsBase is GovernanceAddresses {
    
    Governance public governance;
    address public depositTokenAddress;
    address public governanceTokenAddress;

    constructor() {
        address governanceProxy = vm.parseJsonAddress(addressesJson, ".Governance.proxy");
        governance = Governance(governanceProxy);
        depositTokenAddress = vm.parseJsonAddress(addressesJson, ".tokens.deposit");
        governanceTokenAddress = vm.parseJsonAddress(addressesJson, ".tokens.governance");
        
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
        // Get proposer private key from .env
        uint256 proposerKey = vm.envUint("PROPOSER_PRIVATE_KEY");
        address proposer = vm.addr(proposerKey);
        
        console.log("Proposer address:", proposer);
        
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
        
        vm.startBroadcast(proposerKey);
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

// Arbitrum Sepolia: forge script script/governance/setters/ProposalActions.s.sol:VoteOnProposal --rpc-url $ARBITRUM_SEPOLIA_RPC_URL --broadcast
contract VoteOnProposal is ProposalActionsBase {
    
    bytes32 constant PROPOSAL_ID = 0xbb8b1531a5e00ba9520bdf1569e6ef22519a4728e7e4ae074d7516013d6147bf; // Proposal ID
    bytes constant VOTE_ENCRYPTED = hex"49802f3b216c51f53b2b629b7ea3c7612bcac94b5857d68bdee07506bd29a46d7b5b4ee0f00527be2e404f1c3cbfbe5b4d"; // Encrypted vote data
    
    function run() external {
        // Get voter private key from .env
        uint256 voterKey = vm.envUint("VOTER2_PRIVATE_KEY");
        address voter = vm.addr(voterKey);
        
        console.log("Voter address:", voter);
        
        // Prepare vote arrays
        bytes[] memory voteEncrypteds = new bytes[](1);
        voteEncrypteds[0] = VOTE_ENCRYPTED;
        
        address[] memory delegators = new address[](1);
        delegators[0] = address(0); // No delegation
        
        uint256[] memory delegatorChainIds = new uint256[](1);
        delegatorChainIds[0] = 0;
        
        vm.startBroadcast(voterKey);
        governance.vote(PROPOSAL_ID, voteEncrypteds, delegators, delegatorChainIds);
        vm.stopBroadcast();
        
        console.log("Vote submitted:");
        console.log("  Proposal ID:");
        console.logBytes32(PROPOSAL_ID);
        console.log("  Voter:", voter);
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
    
    bytes32 constant PROPOSAL_ID = 0x4BDD9FF7539E67FCB8AB981E85F2F7B8495B8C3EA155AF4A81CE2FBB5D194B08;
    bytes constant KMS_SIG = hex"b816a234b65045e98aec25ed3b76c900b60a8ad6a23a6dfef3fa27e490ea92f76ff00ff2454985344824ce502efc5ab3374ff6155fa1120d759ec4fa791f4ed91c";
    bytes constant ENCLAVE_PUB_KEY = hex"86053d778893734edd8ad351ef957168e2681fbb098fc81ae266ed9766c4995450a842224bf978a0b024e69087a50ebf958a5851594759b5f96e33f6276648f6";
    bytes constant ENCLAVE_SIG = hex"22eb5e90e7276ecccc3f8b4f7f6ba8273527557a4e61a312efcd9bb7c4c1de0816bb5366ad5261b7a4c7a3cbe6af78e558e3818b0157285eb4897e35b4ac131b1b";
    bytes constant RESULT_DATA = hex"4bdd9ff7539e67fcb8ab981e85f2f7b8495b8c3ea155af4a81ce2fbb5d194b0800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant VOTE_DECRYPTION_KEY = hex"d79f5957ce5b47a0634838d3fe634b03cfc5af075651c5dacd2ae25e2df5a131";

    function run() external {
        // Get proposer private key from .env
        uint256 proposerKey = vm.envUint("PROPOSER_PRIVATE_KEY");
        address proposer = vm.addr(proposerKey);
        
        console.log("Submitter (proposer) address:", proposer);
        
        IGovernanceTypes.SubmitResultInputParams memory params = IGovernanceTypes.SubmitResultInputParams({
            kmsSig: KMS_SIG,
            enclavePubKey: ENCLAVE_PUB_KEY,
            enclaveSig: ENCLAVE_SIG,
            resultData: RESULT_DATA,
            voteDecryptionKey: VOTE_DECRYPTION_KEY
        });
        
        vm.startBroadcast(proposerKey);
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


