// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface ICredit {
    function redeemAndBurn(address _to, uint256 _amount) external;
}
