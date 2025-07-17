// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

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
    error OnlyAdmin();
    error ProposalAlreadyExecuted();
    error ProposalAlreadyExists();
    error ProposalAlreadyInQueue();
    error ProposalAlreadySubmitted();
    error ProposalDoesNotExist();
    error ResultAlreadySubmitted();
    error TokenNotSupported();
    error VotingNotActive();
    error VotingNotDone();
}