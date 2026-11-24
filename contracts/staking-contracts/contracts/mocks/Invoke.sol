// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IClusterSelector {
    function selectClusters() external returns (address[] memory _selectedClusters);
}

contract Invoke {
    constructor() {}

    function selectClusters(IClusterSelector clusterSelector) public returns (address[] memory) {
        return clusterSelector.selectClusters();
    }
}