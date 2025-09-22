// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IClusterSelector.sol";

interface IClusterRewards {
    function clusterSelectors(bytes32 networkId) external returns (IClusterSelector);
    function clusterRewards(address cluster) external returns(uint256);
    function rewardWeight(bytes32 networkId) external returns(uint256);
    function totalRewardsPerEpoch() external returns(uint256);
    function addNetwork(bytes32 networkId, uint256 rewardWeight, address clusterSelector) external;
    function removeNetwork(bytes32 networkId) external;
    function updateNetwork(bytes32 networkId, uint256 updatedRewardWeight, address updatedClusterSelector) external;
    function getRewardForEpoch(uint256 epoch, bytes32 networkId) external view returns(uint256);
    function claimReward(address cluster) external returns(uint256);
    function changeRewardPerEpoch(uint256 updatedRewardPerEpoch) external;
}
