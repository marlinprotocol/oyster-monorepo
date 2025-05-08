// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";

contract OysterServerlessCodeContract is 
    ContextUpgradeable, // _msgSender  
{
    event CodeCreated(address indexed owner, bytes metadata);

    function saveCodeInCallData(string calldata inputData, bytes calldata metadata) external {
        emit CodeCreated(_msgSender(), metadata);
    }
}
