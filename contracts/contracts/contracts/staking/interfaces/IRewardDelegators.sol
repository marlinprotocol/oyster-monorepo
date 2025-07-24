// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IRewardDelegators {
    function thresholdForSelection(bytes32 networkId) external returns(uint256);
    function addRewardFactor(bytes32 _tokenId, uint256 _rewardFactor) external;
    function removeRewardFactor(bytes32 _tokenId) external;
    function updateRewardFactor(bytes32 _tokenId, uint256 _updatedRewardFactor) external;
    function _updateRewards(address _cluster) external;
    function delegate(
        address _delegator,
        address _cluster,
        bytes32[] calldata _tokens,
        uint256[] calldata _amounts
    ) external;
    function undelegate(
        address _delegator,
        address _cluster,
        bytes32[] calldata _tokens,
        uint256[] calldata _amounts
    ) external;
    function withdrawRewards(address _delegator, address _cluster) external returns(uint256);
    function getClusterDelegation(address _cluster, bytes32 _tokenId) external view returns(uint256);
    function getDelegation(address _cluster, address _delegator, bytes32 _tokenId) external view returns(uint256);
    function updateThresholdForSelection(bytes32 networkId, uint256 thresholdForSelection) external;
    function updateStakeAddress(address _updatedStakeAddress) external;
    function updateClusterRewards(address _updatedClusterRewards) external;
    function updateClusterRegistry(address _updatedClusterRegistry) external;
    function updatePONDAddress(address _updatedPOND) external;
    function tokenList(uint256 index) external view returns (bytes32);
    function getAccRewardPerShare(address _cluster, bytes32 _tokenId) external view returns(uint256);
    function updateClusterDelegation(address _cluster, bytes32 _networkId) external;
    function removeClusterDelegation(address _cluster, bytes32 _networkId) external;

    function updateOperatorDelegation(address _operator, bytes memory _data) external;
    function removeOperatorDelegation(address _operator, bytes memory _data) external;

    function lockTokens(
        address _operator,
        bytes32 _lockId,
        uint256 _amount
        // bytes32[] memory _tokens,
        // uint256[] memory _amounts
    ) external;
    function unlockTokens(
        address _operator,
        bytes32 _lockId
    ) external;
    function slash(
        address _operator,
        bytes32 _lockId
    ) external;
    function getTotalDelegation(
        address cluster
    ) external view returns(uint256 _totalWeight, uint256 totalDelegations);
}
