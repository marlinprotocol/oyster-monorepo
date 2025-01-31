// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/Context.sol";
import "../secret-storage/SecretManager.sol";
import "../secret-storage/TeeManager.sol";

contract SecretStoreMock is Context {

    constructor(
        address _teeManagerAddress
    ) {
        TEE_MANAGER = TeeManager(_teeManagerAddress);
    }

    TeeManager public TEE_MANAGER;

    SecretManager public SECRET_MANAGER;

    struct SecretStorage {
        uint256 storageCapacity;
        uint256 storageOccupied;
        uint256 lastAliveTimestamp;
        uint256 deadTimestamp;
        uint256[] ackSecretIds;
    }

    // enclaveAddress => Storage node details
    mapping(address => SecretStorage) public secretStores;

    event SecretStoreMockStakeAdded(
        address enclaveAddress,
        uint8 env,
        uint256 stake
    );

    event SecretStoreMockNodeUpserted(
        uint8 env,
        address enclaveAddress,
        uint256 stakeAmount
    );

    event SecretStoreMockNodeDeleted(
        uint8 env,
        address enclaveAddress
    );

    function setSecretManager(address _secretManagerAddress) external {
        SECRET_MANAGER = SecretManager(_secretManagerAddress);
    }

    function registerSecretStore(
        address _enclaveAddress,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) external {
        secretStores[_enclaveAddress].storageCapacity = _storageCapacity;
        secretStores[_enclaveAddress].lastAliveTimestamp = block.timestamp;
    }

    function addSecretStoreStake(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stake
    ) external {
        emit SecretStoreMockStakeAdded(_enclaveAddress, _env, _stake);
    }

    function selectNonAssignedSecretStore(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit,
        address[] memory _selectedStoresToIgnore
    ) external returns (SecretManager.SelectedEnclave[] memory) {
        SecretManager.SelectedEnclave[] memory selectedStores = new SecretManager.SelectedEnclave[](1);
        selectedStores[0] = SecretManager.SelectedEnclave({
            enclaveAddress: address(1),
            hasAcknowledgedStore: true,
            selectTimestamp: block.timestamp,
            replacedAckTimestamp: 0
        });
        return selectedStores;
    }

    function selectStores(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) external returns (SecretManager.SelectedEnclave[] memory) {
        SecretManager.SelectedEnclave[] memory selectedStores = new SecretManager.SelectedEnclave[](_noOfNodesToSelect);
        for (uint256 index = 0; index < _noOfNodesToSelect; index++) {
            selectedStores[index] = SecretManager.SelectedEnclave({
                enclaveAddress: storesToSelect[index],
                hasAcknowledgedStore: false,
                selectTimestamp: block.timestamp,
                replacedAckTimestamp: 0
            });
            secretStores[storesToSelect[index]].storageOccupied += _sizeLimit;
        }
        return selectedStores;
    }

    function renounceSecrets(
        address _enclaveAddress,
        address _owner
    ) external returns (uint256 /* occupiedStorage */) {
        uint256 lastAliveTimestamp = secretStores[_enclaveAddress].lastAliveTimestamp;
        // pre-update
        secretStores[_enclaveAddress].lastAliveTimestamp = block.timestamp;

        uint256 occupiedStorage = SECRET_MANAGER.renounceSecrets(
            _enclaveAddress,
            _owner,
            secretStores[_enclaveAddress].ackSecretIds,
            lastAliveTimestamp
        );

        // post-update
        secretStores[_enclaveAddress].storageOccupied -= occupiedStorage;
        delete secretStores[_enclaveAddress].ackSecretIds;

        return occupiedStorage;
    }

    function addAckSecretIdToStore(
        address _enclaveAddress,
        uint256 _ackSecretId
    ) external {
        secretStores[_enclaveAddress].ackSecretIds.push(_ackSecretId);
    }

    address[] public storesToSelect;

    function setStoresToSelect(
        address[] memory _stores
    ) external {
        storesToSelect = _stores;
    }

    function markAliveUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) external {
        secretStores[_enclaveAddress].lastAliveTimestamp = _currentCheckTimestamp;
    }

    function getSecretStoreLastAliveTimestamp(address _enclaveAddress) external view returns (uint256) {
        return secretStores[_enclaveAddress].lastAliveTimestamp;
    }

    function getSecretStoreDeadTimestamp(address _enclaveAddress) external view returns (uint256) {
        return secretStores[_enclaveAddress].deadTimestamp;
    }

    function getStoreAckSecretIds(address _enclaveAddress) external view returns (uint256[] memory) {
        return secretStores[_enclaveAddress].ackSecretIds;
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
        emit SecretStoreMockNodeUpserted(_env, _enclaveAddress, _stakeAmount);
    }

    function deleteTreeNodeIfPresent(
        uint8 _env,
        address _enclaveAddress
    ) external {
        emit SecretStoreMockNodeDeleted(_env, _enclaveAddress);
    }

}
