// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IClusterSelector {
    /// @notice Add an element to tree. If the element already exists, it will be updated
    /// @param newNode Address of the node to add
    /// @param balance Balance of the node
    function upsert(address newNode, uint64 balance) external;

    /// @notice function add multiple addresses in one call
    /// @param newNodes newNodes of the node nodes
    /// @param balances Balances of the new nodes.
    function upsertMultiple(address[] calldata newNodes, uint64[] calldata balances) external;

    /// @notice Update the balance of the node
    /// @param cluster Address of the existing node
    /// @param clusterBalance new balance of the node
    function update_unchecked(address cluster, uint64 clusterBalance) external;

    /// @notice Delete a node from the tree
    /// @param key Address of the node to delete
    function delete_unchecked(address key) external;

    /// @notice Insert the node with given balance (unchecked)
    /// @param newNode Address of the new node
    /// @param balance Balance of the new node
    function insert_unchecked(address newNode, uint64 balance) external;

    /// @notice Insert multiple nodes with given balances (unchecked)
    /// @param newNodes Addresses of the new nodes
    /// @param balances Balances of the new nodes
    function insertMultiple_unchecked(address[] calldata newNodes, uint64[] calldata balances) external;

    /// @notice timestamp when the selector starts
    function START_TIME() external view returns(uint256);

    /// @notice length of epoch
    function EPOCH_LENGTH() external view returns(uint256);

    /// @notice no of cluster selected in an epoch
    function NUMBER_OF_CLUSTERS_TO_SELECT() external view returns(uint256);

    /// @notice Current Epoch
    function getCurrentEpoch() external view returns (uint256);

    /// @notice Clusters are selected only for next epoch in this epoch using selectClusters method.
    /// If the method is not called within the previous epoch, then the last selected clusters
    /// are considered as selected for this epoch
    /// @param epoch Epoch Number
    function getClusters(uint256 epoch) external view returns (address[] memory clusters);

    /// @notice Clusters are selected only for next epoch in this epoch using selectClusters method.
    /// If the method is not called within the previous epoch, then the last selected clusters
    /// are considered as selected for this epoch
    /// @param from Epoch Number
    /// @param to Epoch Number
    function getClustersRanged(uint256 from, uint256 to) external view returns (address[][] memory clusters);

    /// @notice Returns the list of selected clusters for the next
    /// @return nodes List of the clusters selected
    function selectClusters() external returns (address[] memory nodes);

    /// @notice Delete a node from tree if it is stored
    /// @param key Address of the node
    function deleteIfPresent(address key) external;

    /// @notice Update the number of clusters to select
    /// @param numberOfClusters New number of clusters to select
    function updateNumberOfClustersToSelect(uint256 numberOfClusters) external;
}
