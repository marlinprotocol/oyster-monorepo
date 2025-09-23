// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

interface IGovernanceErrors {
    error InvalidChainId();
    error InvalidDescriptionLength();
    error InvalidEnclaveSignature();
    error InvalidInputLength();
    error InvalidKMSPath();
    error InvalidKMSRootServerPubKey();
    error InvalidMaxRpcUrlsPerChain();
    error InvalidMsgValue();
    error InvalidPCRLength();
    error InvalidProposalTimeConfig();
    error InvalidPubKeyLength();
    error InvalidRpcUrl();
    error InvalidTitleLength();
    error InvalidVoteIndex();
    error InvalidVetoSlashRate();
    error InvadidKMSSignature();
    error MaxRpcUrlsPerChainReached();
    error NoSupportedChainConfigured();
    error NotConfigSetterRole();
    error NotDefaultAdmin();
    error NoValueToRefund();
    error NotRefundableProposal();
    error NotResultSubmissionPhase();
    error ProposalAlreadyExists();
    error ProposalAlreadyInQueue();
    error ProposalAlreadySubmitted();
    error ProposalDoesNotExist();
    error ProposalNotInQueue();
    error ResultAlreadySubmitted();
    error ResultHashMismatch();
    error SameImageId();
    error TokenNotSupported();
    error VotingNotActive();
    error ZeroProposalPassThreshold();
    error ZeroProposalTimeConfig();
    error InvalidMinQuorumThreshold();
    error InvalidAddress();
    error InvalidDelegatorChainId();
}