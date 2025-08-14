// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IOperatorRewards {
    function claimReward(address operator) external returns(uint256);
}