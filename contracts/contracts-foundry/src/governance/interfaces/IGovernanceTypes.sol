// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

interface IGovernanceTypes {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    enum VoteOutcome {
        Pending,
        Passed,
        Failed,
        Vetoed
    }
    struct ProposalInfo {
        address proposer;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        string title;
        string description;
    }

    /// @notice Information about a proposal's timing
    struct ProposalTimeInfo {
        uint256 proposedTimestamp;
        uint256 voteActivationTimestamp;
        uint256 voteDeadlineTimestamp;
        uint256 proposalDeadlineTimestamp;
    }

    struct TokenLockInfo {
        address token;
        uint256 amount;
    }

    struct Vote {
        address voter;
        bytes voteEncrypted;
    }

    struct VoteDecisionResult {
        uint256 yes;
        uint256 no;
        uint256 abstain;
        uint256 noWithVeto;
        uint256 totalVotingPower;
    }

    struct ProposalVoteInfo {
        bytes32 voteHash;
        uint256 voteCount;
        mapping(uint256 voteIdx => Vote vote) votes;
    }

    struct TokenNetworkConfig {
        bytes32 chainHash; // keccak256(abi.encode(chainId, rpcUrls))
        address tokenAddress;
        string[] rpcUrls;
    }

    struct Proposal {
        TokenLockInfo tokenLockInfo;
        ProposalInfo proposalInfo;
        ProposalTimeInfo proposalTimeInfo;
        ProposalVoteInfo proposalVoteInfo;
        VoteOutcome voteOutcome;
        bytes32 imageId;
        bytes32 networkHash;
        bool executed;
    }

    // vote activation: proposedTimestamp + voteActivationDelay
    // vote deadline: proposedTimestamp + voteActivationDelay + voteDuration
    // proposal deadline: proposedTimestamp + proposalDuration
    struct ProposalTimingConfig {
        uint256 voteActivationDelay;
        uint256 voteDuration;
        uint256 proposalDuration;
    }

    struct PCRConfig {
        PCR pcr;
        bytes32 imageId;
    }

    struct PCR {
        bytes pcr0;
        bytes pcr1;
        bytes pcr2;
    }


    /*//////////////////////////////////////////////////////////////
                                 PARAMS
    //////////////////////////////////////////////////////////////*/

    struct ProposeInputParams {
        address depositToken;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        string title;
        string description;
    }
    
    struct SubmitResultInputParams {
        bytes kmsSig;
        bytes enclavePubKey;
        bytes enclaveSig;
        bytes resultData;
    }
}