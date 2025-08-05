// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

contract MockTarget {
    uint256 public value;
    address public lastCaller;
    
    event ValueSet(uint256 newValue, address caller);
    
    function setValue(uint256 _value) external payable {
        value = _value;
        lastCaller = msg.sender;
        emit ValueSet(_value, msg.sender);
    }
    
    function transferETH(address payable _recipient) external payable {
        (bool success, ) = _recipient.call{value: msg.value}("");
        require(success, "Transfer failed");
    }
    
    receive() external payable {}
} 