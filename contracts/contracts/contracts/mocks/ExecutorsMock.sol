// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/Context.sol";
import "../secret-storage/TeeManager.sol";

contract ExecutorsMock is Context {

    constructor(
        address _teeManagerAddress
    ) {
        TEE_MANAGER = TeeManager(_teeManagerAddress);
    }

    TeeManager public TEE_MANAGER;

    uint256 public constant INIT_REPUTATION = 1000;

    struct Executor {
        uint256 jobCapacity;
        uint256 activeJobs;
        uint256 reputation;
    }

    // enclaveAddress => executor node details
    mapping(address => Executor) public executors;

    event ExecutorMockStakeAdded(
        address enclaveAddress,
        uint8 env,
        uint256 stake
    );

    event ExecutorsMockNodeUpserted(
        uint8 env,
        address enclaveAddress,
        uint256 stakeAmount
    );

    event ExecutorsMockNodeDeleted(
        uint8 env,
        address enclaveAddress
    );

    function registerExecutor(
        address _enclaveAddress,
        uint256 _jobCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) external {
        executors[_enclaveAddress].jobCapacity = _jobCapacity;
        executors[_enclaveAddress].reputation = INIT_REPUTATION;
    }

    function addExecutorStake(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stake
    ) external {
        emit ExecutorMockStakeAdded(_enclaveAddress, _env, _stake);
    }

    function updateTreeState(
        address _enclaveAddress
    ) external {
        TEE_MANAGER.updateTreeState(_enclaveAddress);
    }

    function upsertTreeNode(
        uint8 _env,
        address _enclaveAddress,
        uint256 _stakeAmount
    ) external {
        emit ExecutorsMockNodeUpserted(_env, _enclaveAddress, _stakeAmount);
    }

    function deleteTreeNodeIfPresent(
        uint8 _env,
        address _enclaveAddress
    ) external {
        emit ExecutorsMockNodeDeleted(_env, _enclaveAddress);
    }

}
