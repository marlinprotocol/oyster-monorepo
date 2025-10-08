// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./IGovernanceTypes.sol";

interface IGovernanceEvents is IGovernanceTypes {
    event TokenLockAmountSet(address token, uint256 amount);
    event VoteActivationDelaySet(uint256 delay);
    event VoteDurationSet(uint256 duration);
    event ProposalDurationSet(uint256 duration);
    event NetworkConfigSet(uint256 chainId, address tokenAddress, string[] rpcUrls, bytes32 networkHash);
    event RpcUrlUpdated(uint256 indexed chainId, string[] rpcUrls);
    event KMSRootServerPubKeySet(bytes kmsRootServerPubKey);
    event PCRConfigSet(bytes pcr0, bytes pcr1, bytes pcr2, bytes32 indexed imageId);
    event GovernanceEnclaveSet(address indexed governanceEnclave);
    event TreasurySet(address indexed treasury);
    event MaxRpcUrlsPerChainSet(uint256 maxRpcUrlsPerChain);
    event ProposalPassVetoThresholdSet(uint256 threshold);
    event MinQuorumThresholdSet(uint256 minQuorum);
    event VetoSlashRateSet(uint256 vetoSlashRate);
    event ExpiredProposalRefunded(
        bytes32 indexed proposalId
    );

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
        address indexed voter,
        address indexed delegator,
        uint256 delegatorChainId,
        uint256 voteIdx,
        bytes voteEncrypted
    );

    event ResultSubmitted(
        bytes32 indexed proposalId,
        VoteDecisionResult voteDecisionResult,
        VoteOutcome voteOutcome
    );

    event ProposalExecuted(
        bytes32 indexed proposalId
    );

    event GovernanceDelegationSet(uint256 indexed chainId, address indexed governanceDelegation);
}