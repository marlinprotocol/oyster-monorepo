// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

interface IGovernanceErrors {
    error Governance__InvalidChainId();
    error Governance__InvalidDescriptionLength();
    error Governance__InvalidEnclaveSignature();
    error Governance__InvalidInputLength();
    error Governance__InvalidKMSPath();
    error Governance__InvalidKMSRootServerPubKey();
    error Governance__InvalidMaxRpcUrlsPerChain();
    error Governance__InvalidMsgValue();
    error Governance__InvalidPCRLength();
    error Governance__InvalidProposalTimeConfig();
    error Governance__InvalidRpcUrl();
    error Governance__InvalidRpcUrlIndex();
    error Governance__InvalidTitleLength();
    error Governance__InvalidVoteIndex();
    error Governance__InvalidVetoSlashRate();
    error Governance__InvalidKMSSignature();
    error Governance__MaxRpcUrlsPerChainReached();
    error Governance__NoSupportedChainConfigured();
    error Governance__OnlyConfigSetter();
    error Governance__OnlyDefaultAdmin();
    error Governance__NoValueToRefund();
    error Governance__NotRefundableProposal();
    error Governance__NotResultSubmissionPhase();
    error Governance__ProposalAlreadyExists();
    error Governance__ProposalAlreadyInQueue();
    error Governance__ProposalAlreadySubmitted();
    error Governance__ProposalDoesNotExist();
    error Governance__ProposalNotInQueue();
    error Governance__ResultAlreadySubmitted();
    error Governance__ResultHashMismatch();
    error Governance__SameImageId();
    error Governance__TokenNotSupported();
    error Governance__VotingNotActive();
    error Governance__ZeroProposalPassThreshold();
    error Governance__ZeroProposalTimeConfig();
    error Governance__InvalidMinQuorumThreshold();
    error Governance__InvalidAddress();
    error Governance__InvalidDelegatorAndChainId();
    error Governance__InvalidDelegatorChainId();
}
