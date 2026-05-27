// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

contract MockGovernanceReceptor {
    event TriggeredWithWei();
    event Triggered();

    function actWithWei(bool, uint256, bytes calldata, uint256 w) external payable {
        require(msg.value == w, "not valid");
        emit TriggeredWithWei();
    }

    function act(string calldata, address, bytes32, uint8) external {
        emit Triggered();
    }
}
