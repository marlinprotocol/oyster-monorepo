// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";


interface IUSDCMock {
    function mint(address to, uint256 amount) external;
    function decimals() external pure returns (uint8);
    function grantRole(bytes32 role, address account) external;
}