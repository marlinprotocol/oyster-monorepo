// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IGovernanceTypes} from "./IGovernanceTypes.sol";
import {IGovernanceErrors} from "./IGovernanceErrors.sol";
import {IGovernanceEvents} from "./IGovernanceEvents.sol";

interface IGovernance is IGovernanceErrors, IGovernanceTypes, IGovernanceEvents {
    // Delegation chain IDs
    function getDelegationChainIdsLength() external view returns (uint256);
    function getAllDelegationChainIds() external view returns (uint256[] memory);

    // Proposal timing config
    function getProposalTimingConfig()
        external
        view
        returns (uint256 voteActivationDelay, uint256 voteDuration, uint256 proposalDuration);

    // Proposal hashes
    function getProposalHashes(bytes32 _proposalId) external view returns (bytes32, bytes32, bytes32);
}
