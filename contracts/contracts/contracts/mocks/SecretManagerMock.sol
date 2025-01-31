// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/Context.sol";
import "../secret-storage/SecretStore.sol";
import "../secret-storage/SecretManager.sol";

contract SecretManagerMock is Context {

    constructor(
        address _secretStoreAddress
    ) {
        SECRET_STORE = SecretStore(_secretStoreAddress);
        GLOBAL_MAX_STORE_SIZE = 1e6;
        MARK_ALIVE_TIMEOUT = 500;
        STAKING_PAYMENT_POOL = address(1);
    }

    SecretStore public immutable SECRET_STORE;

    uint256 public immutable GLOBAL_MAX_STORE_SIZE;

    uint256 public immutable MARK_ALIVE_TIMEOUT;

    address public immutable STAKING_PAYMENT_POOL;

    function selectStores(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) external returns (SecretManager.SelectedEnclave[] memory) {
        return SECRET_STORE.selectStores(_env, _noOfNodesToSelect, _sizeLimit);
    }

    function selectNonAssignedSecretStore(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit,
        address[] memory _selectedStoresToIgnore
    ) external returns (SecretManager.SelectedEnclave[] memory) {
        return SECRET_STORE.selectNonAssignedSecretStore(_env, _noOfNodesToSelect, _sizeLimit, _selectedStoresToIgnore);
    }

    function releaseStore(
        address _enclaveAddress,
        uint256 _secretSize
    ) external {
        SECRET_STORE.releaseStore(_enclaveAddress, _secretSize);
    }

    function markAliveUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) external {
        SECRET_STORE.markAliveUpdate(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
    }

    function markDeadUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        uint256 _storageOccupied,
        address _recipient
    ) external {
        SECRET_STORE.markDeadUpdate(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _storageOccupied, _recipient);
    }

    function secretTerminationUpdate(
        address _enclaveAddress,
        uint256 _secretSize,
        uint256 _secretId
    ) external {
        SECRET_STORE.secretTerminationUpdate(_enclaveAddress, _secretSize, _secretId);
    }

    function addAckSecretIdToStore(
        address _enclaveAddress,
        uint256 _ackSecretId
    ) external {
        SECRET_STORE.addAckSecretIdToStore(_enclaveAddress, _ackSecretId);
    }

    function renounceSecrets(
        address _enclaveAddress,
        address _owner,
        uint256[] memory _storeAckSecretIds,
        uint256 _lastAliveTimestamp
    ) external returns (uint256 /* occupiedStorage */) {
        return 0;
    }

}