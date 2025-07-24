// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IOperatorSelector {
    function updateOperatorSelector(address operator, uint256 totalDelegation) external;

    function removeOperatorSelector(address operator) external;
}