// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

interface IGovernanceErrors {
    error InvalidChainId();
    error InvalidDescriptionLength();
    error InvalidEnclaveSignature();
    error InvalidInputLength();
    error InvalidPCR16Sha256();
    error InvalidProposalTimeConfig();
    error InvalidPubKeyLength();
    error InvalidRpcUrl();
    error InvalidTitleLength();
    error InvalidTokenAddress();
    error InvalidVoteResult();
    error InvadidKMSSignature();
    error NotResultSubmissionPhase();
    error NotDefaultAdmin();
    error ProposalAlreadyExecuted();
    error ProposalAlreadyExists();
    error ProposalAlreadyInQueue();
    error ProposalAlreadySubmitted();
    error ProposalDoesNotExist();
    error ResultAlreadySubmitted();
    error TokenNotSupported();
    error VotingNotActive();
    error VotingNotDone();
    error InvalidTargetAddress();
    error ProposalNotInQueue();
    error InvalidMsgValue();
    error NotConfigSetterRole();
    error NoSupportedChainConfigured();
    error ZeroAdminAddress();
    error ZeroConfigSetterAddress();
    error ZeroProposalTimeConfig();
    error InvalidPCRLength();
    error ZeroTreasuryAddress();
    error MaxRpcUrlsPerChainReached();
    error InvalidMaxRpcUrlsPerChain();
    error ZeroProposalPassThreshold();
}