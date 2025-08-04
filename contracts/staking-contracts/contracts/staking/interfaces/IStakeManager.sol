// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IStakeManager {
    function stashes(bytes32 _stashId) external returns(address, address);
    function stashIndex() external returns(uint256);
    function locks(bytes32 _lockId) external returns(uint256, uint256);
    function lockWaitTime(bytes32 _selectorId) external returns(uint256);
    function updateLockWaitTime(bytes32 _selector, uint256 _updatedWaitTime) external;
    function updateRewardDelegators(address _updatedRewardDelegator) external;
    function disableToken(bytes32 _tokenId) external;
    function createStashAndDelegate(
        bytes32[] calldata _tokens,
        uint256[] calldata _amounts,
        address _delegatedCluster
    ) external;
    function createStash(bytes32[] calldata _tokens, uint256[] calldata _amounts) external returns(bytes32);
    function delegateStash(bytes32 _stashId, address _delegatedCluster) external;
    function requestStashRedelegation(bytes32 _stashId, address _newCluster) external;
    function redelegateStash(bytes32 _stashId) external;
    function undelegateStash(bytes32 _stashId) external;
    function withdrawStash(bytes32 _stashId) external;
    function withdrawStash(bytes32 _stashId, bytes32[] calldata _tokens, uint256[] calldata _amounts) external;
    function stashes__amounts(bytes32 _stashId, bytes32 _tokenId) external view returns(uint256);
    function transferSlashedToken(
        bytes32 _tokenId,
        uint256 _amount,
        address _recipient
    ) external returns (address token);
}
