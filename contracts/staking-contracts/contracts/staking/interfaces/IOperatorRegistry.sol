// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IOperatorRegistry {
    function addService(
        bytes32 _operatorManagerId,
        address _operatorManager,
        address _operatorRewards,
        address _operatorSelector,
        address _rewardToken,
        bool _isTwoStepDeregister
    ) external;

    function register(address _operator, bytes32 _operatorManagerId, bytes memory _data) external;

    function requestDeregister(bytes memory _data) external;

    function deregister(bytes memory _data) external;

    function operatorToManagerId(address _operator) external view returns (bytes32);

    function getOperatorManager(bytes32 _operatorManagerId) external view returns (address);

    function getOperatorRewards(bytes32 _operatorManagerId) external view returns (address);

    function getOperatorSelector(bytes32 _operatorManagerId) external view returns (address);
    
    function getRewardToken(bytes32 _operatorManagerId) external view returns (address);
}