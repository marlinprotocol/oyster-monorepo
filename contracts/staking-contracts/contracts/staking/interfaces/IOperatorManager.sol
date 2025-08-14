// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IOperatorManager {
    function registerOperator(
        address _operator,
        bytes calldata _data
    ) external;
    function getRewardInfo(address _operator) external returns(uint256, address);
}