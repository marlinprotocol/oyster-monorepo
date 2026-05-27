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
    bytes constant VOTE_ENCRYPTED =
        hex"49802f3b216c51f53b2b629b7ea3c7612bcac94b5857d68bdee07506bd29a46d7b5b4ee0f00527be2e404f1c3cbfbe5b4d"; // Encrypted vote data

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
    bytes32 constant PROPOSAL_ID = 0x572259748840B294EF1A7DD08281A01723ECD1AF5B63A8202220E39D1BB03FC2;
    bytes constant KMS_SIG =
        hex"de0ac1df8d53bc88318ccafe967fdfc97c88a8dcca2285644e531c7a5cdf3b5538d2dbf76dfbae85c5cfa087eaad506e50b3f2b6f7c8704429c9d41f34f77d4c1b";
    bytes constant ENCLAVE_PUB_KEY =
        hex"3ca240e531add5c6180cb5d80d39889e0249236b4c436ea06c2ec4fad35b3b05fd5be01bf3f0483e2db81e98cc8764d0ae2294afaa3d1674f3d9043e76c4dbff";
    bytes constant ENCLAVE_SIG =
        hex"0d03a3be015881f3ede00a84302f5b8e4413504d128addb4677eb3a0006cea8b39c0084ffcd3ce0c5636062d1854847d16388a6ec99bef5c0a223e3849b113ca1c";
    bytes constant RESULT_DATA =
        hex"572259748840b294ef1a7dd08281a01723ecd1af5b63a8202220e39d1bb03fc200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant VOTE_DECRYPTION_KEY = hex"446203397a0071fb0f59e2bb5e2e23b817c90a7c2138bf1c42e0c213a13de280";

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
