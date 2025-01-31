// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../secret-storage/Executors.sol";

contract ExecutorsUser {

    constructor(
        address _executorsAddress
    ) {
        EXECUTORS = Executors(_executorsAddress);
    }

    Executors public EXECUTORS;

    event ExecutorsUserNodesSelected(address[] selectedNodes);
    event ExecutorsUserNodeSlashed(uint256 slashedAmount);

    function selectExecutionNodes(
        uint8 _env,
        address[] memory selectedStores,
        uint256 _noOfNodesToSelect
    ) external {
        address[] memory selectedNodes = EXECUTORS.selectExecutionNodes(_env, selectedStores, _noOfNodesToSelect);
        emit ExecutorsUserNodesSelected(selectedNodes);
    }

    function slashExecutor(address _enclaveAddress) external {
        uint256 slashedAmount = EXECUTORS.slashExecutor(_enclaveAddress);
        emit ExecutorsUserNodeSlashed(slashedAmount);
    }

}
