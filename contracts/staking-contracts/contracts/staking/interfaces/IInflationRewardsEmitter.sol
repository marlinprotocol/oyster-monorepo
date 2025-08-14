// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IInflationRewardsEmitter {
    function getCurrentEpoch() external returns (uint256);

    function emitInflationaryReward() external returns (uint256);

    function rewardToken() external view returns (IERC20);
}