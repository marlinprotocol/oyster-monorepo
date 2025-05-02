// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OysterServerlessCodeContract {

    event CodeCreated(bytes metadata);

    function saveCodeInCallData(string calldata inputData, bytes calldata metadata) external {
        emit CodeCreated(metadata);
    }
}
