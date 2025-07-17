// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./IGovernanceTypes.sol";

interface IGovernanceEvents is IGovernanceTypes {
    event TokenLockAmountSet(address token, uint256 amount);
    event VoteActivationDelaySet(uint256 delay);
    event VoteDurationSet(uint256 duration);
    event ProposalDurationSet(uint256 duration);
    event NetworkConfigSet(uint256 chainId, address tokenAddress, string[] rpcUrls);
    event RpcUrlAdded(uint256 indexed chainId, string rpcUrl);
    event RpcUrlUpdated(uint256 indexed chainId, uint256 index, string rpcUrl);
    event KMSRootServerPubKeySet(bytes kmsRootServerPubKey);
    event KMSPathSet(string kmsPath);
    event PCRConfigSet(bytes pcr0, bytes pcr1, bytes pcr2);
    event TreasurySet(address indexed treasury);
    event MaxRpcUrlsPerChainSet(uint256 maxRpcUrlsPerChain);
    event DepositLocked(
        bytes32 indexed proposalId,
        address token,
        uint256 amount
    );
    event DepositRefunded(
        bytes32 indexed proposalId,
        address token,
        uint256 amount
    );
    event DepositSlashed(
        bytes32 indexed proposalId,
        address token,
        uint256 amount
    );
    event ValueRefunded(
        bytes32 indexed proposalId,
        address indexed proposer,
        uint256 totalValue
    );

    event ProposalCreated(
        bytes32 indexed proposalId,
        address indexed proposer,
        uint256 nonce,
        address[] targets,
        uint256[] values,
        bytes[] calldatas,
        string title,
        string description,
        ProposalTimeInfo proposalTimeInfo
    );

    event VoteSubmitted(
        bytes32 indexed proposalId,
        uint256 indexed voteIdx,
        address indexed voter,
        bytes voteEncryped
    );

    event ResultSubmitted(
        bytes32 indexed proposalId,
        VoteDecisionCount voteDecisionCount,
        VoteOutcome voteOutcome
    );

    event ProposalExecuted(
        bytes32 indexed proposalId

    );
}