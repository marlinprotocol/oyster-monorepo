// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../serverless-v2/tree/TreeMapUpgradeable.sol";
import "./SecretManager.sol";
import "./TeeManager.sol";

/**
 * @title SecretStore Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract SecretStore is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    TreeMapUpgradeable
{
    /// @notice Thrown when the provided TeeManager address is zero.
    error SecretStoreZeroAddressTeeManager();

    /**
     * @dev Initializes the logic contract without any admins, safeguarding against takeover.
     * @param _teeManager The TeeManager contract.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        TeeManager _teeManager
    ) {
        _disableInitializers();

        if (address(_teeManager) == address(0)) revert SecretStoreZeroAddressTeeManager();

        TEE_MANAGER = _teeManager;
    }

    //-------------------------------- Overrides start --------------------------------//

    /// @inheritdoc ERC165Upgradeable
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    /// @notice Thrown when the provided admin address is zero.
    error SecretStoreZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin.
     * @param _admin The address of the admin.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert SecretStoreZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __TreeMapUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        MIN_STAKE_AMOUNT = TEE_MANAGER.MIN_STAKE_AMOUNT();
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    TeeManager public immutable TEE_MANAGER;

    /// @notice enclave stake amount will be divided by 10^18 before adding to the tree
    uint256 public constant STAKE_ADJUSTMENT_FACTOR = 1e18;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    uint256 public MIN_STAKE_AMOUNT;

    SecretManager public SECRET_MANAGER;

    //-------------------------------- SecretStore start --------------------------------//

    modifier onlyTeeManager() {
        _onlyTeeManager();
        _;
    }

    function _onlyTeeManager() internal view {
        if (_msgSender() != address(TEE_MANAGER))
            revert SecretStoreNotTeeManager();
    }

    modifier onlySecretManager() {
        _onlySecretManager();
        _;
    }

    function _onlySecretManager() internal view {
        if (_msgSender() != address(SECRET_MANAGER))
            revert SecretStoreNotSecretManager();
    }

    struct SecretStorage {
        uint256 storageCapacity;
        uint256 storageOccupied;
        uint256 lastAliveTimestamp;
        uint256 deadTimestamp;
        uint256[] ackSecretIds;
    }

    // enclaveAddress => Storage node details
    mapping(address => SecretStorage) public secretStores;

    error SecretStoreGlobalEnvAlreadySupported();
    error SecretStoreGlobalEnvAlreadyUnsupported();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that has pending jobs.
    error SecretStoreHasOccupiedStorage();
    /// @notice Thrown when the provided enclave owner does not match the stored owner.
    error SecretStoreNotTeeManager();
    /// @notice Thrown when the caller is not the SecretManager contract.
    error SecretStoreNotSecretManager();
    /// @notice Thrown when the provided execution environment is not supported globally.
    error SecretStoreUnsupportedEnv();

    modifier isValidEnv(uint8 _env) {
        _isValidEnv(_env);
        _;
    }

    function _isValidEnv(uint8 _env) internal view {
        if (!isTreeInitialized(_env)) 
            revert SecretStoreUnsupportedEnv();
    }

    //-------------------------------- Admin methods start --------------------------------//

    function setSecretManager(address _secretManagerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        SECRET_MANAGER = SecretManager(_secretManagerAddress);
    }

    //-------------------------------- Admin methods start --------------------------------//

    //-------------------------------- JobsRole functions end ------------------------------------//

    function initTree(uint8 _env) external onlyRole(JOBS_ROLE) {
        if (isTreeInitialized(_env)) 
            revert SecretStoreGlobalEnvAlreadySupported();

        _init_tree(_env);
    }

    function removeTree(uint8 _env) external onlyRole(JOBS_ROLE) {
        if (!isTreeInitialized(_env)) 
            revert SecretStoreGlobalEnvAlreadyUnsupported();

        _delete_tree(_env);
    }

    //-------------------------------- JobsRole functions end ------------------------------------//

    //---------------------------- TeeManagerRole functions start ---------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _registerSecretStore(
        address _enclaveAddress,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) internal {
        secretStores[_enclaveAddress].storageCapacity = _storageCapacity;
        secretStores[_enclaveAddress].lastAliveTimestamp = block.timestamp;

        // add node to the tree if min stake amount deposited
        if (_stakeAmount >= MIN_STAKE_AMOUNT)
            _insert_unchecked(_env, _enclaveAddress, uint64(_stakeAmount / STAKE_ADJUSTMENT_FACTOR));
    }

    function _drainSecretStore(
        address _enclaveAddress,
        uint8 _env
    ) internal {
        // remove node from the tree
        _deleteIfPresent(_env, _enclaveAddress);
    }

    function _reviveSecretStore(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stakeAmount
    ) internal {
        secretStores[_enclaveAddress].lastAliveTimestamp = block.timestamp;
        // insert node in the tree
        if (
            secretStores[_enclaveAddress].storageOccupied < 
            (secretStores[_enclaveAddress].storageCapacity - SECRET_MANAGER.GLOBAL_MAX_STORE_SIZE())
        ) {
            _insert_unchecked(_env, _enclaveAddress, uint64(_stakeAmount / STAKE_ADJUSTMENT_FACTOR));
        }
    }

    function _deregisterSecretStore(address _enclaveAddress) internal {
        if (secretStores[_enclaveAddress].storageOccupied != 0) 
            revert SecretStoreHasOccupiedStorage();

        delete secretStores[_enclaveAddress];
    }

    function _upsertTreeNode(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stake
    ) internal {
        if (
            secretStores[_enclaveAddress].storageOccupied < 
            (secretStores[_enclaveAddress].storageCapacity - SECRET_MANAGER.GLOBAL_MAX_STORE_SIZE())
        ) {
            // if prevStake is less than min stake, then insert node in tree, else update the node value in tree
            _upsert(_env, _enclaveAddress, uint64(_stake / STAKE_ADJUSTMENT_FACTOR));
        }
    }

    function _removeSecretStoreStake(address _enclaveAddress) internal view {
        if (secretStores[_enclaveAddress].storageOccupied != 0) 
            revert SecretStoreHasOccupiedStorage();
    }

    function _renounceSecrets(
        address _enclaveAddress,
        address _owner
    ) internal {
        uint256 lastAliveTimestamp = secretStores[_enclaveAddress].lastAliveTimestamp;
        _renounceSecretsPreUpdate(
            _enclaveAddress,
            SECRET_MANAGER.MARK_ALIVE_TIMEOUT(),
            SECRET_MANAGER.STAKING_PAYMENT_POOL()
        );

        uint256 occupiedStorage = SECRET_MANAGER.renounceSecrets(
            _enclaveAddress,
            _owner,
            secretStores[_enclaveAddress].ackSecretIds,
            lastAliveTimestamp
        );

        _renounceSecretsPostUpdate(_enclaveAddress, occupiedStorage);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function registerSecretStore(
        address _enclaveAddress,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) external isValidEnv(_env) onlyTeeManager {
        _registerSecretStore(
            _enclaveAddress,
            _storageCapacity,
            _env,
            _stakeAmount
        );
    }

    /**
     * @notice Deregisters an enclave node.
     * @param _enclaveAddress The address of the enclave to deregister.
     * @dev Caller must be the owner of the enclave node.
     */
    function deregisterSecretStore(address _enclaveAddress) external onlyTeeManager {
        _deregisterSecretStore(_enclaveAddress);
    }

    /**
     * @notice Drains an enclave node, making it inactive for new secret stores.
     * @param _enclaveAddress The address of the enclave to drain.
     * @dev Caller must be the owner of the enclave node.
     */
    function drainSecretStore(
        address _enclaveAddress,
        uint8 _env,
        address _owner
    ) external onlyTeeManager {
        _drainSecretStore(_enclaveAddress, _env);
        _renounceSecrets(_enclaveAddress, _owner);
    }

    /**
     * @notice Revives a previously drained enclave node.
     * @param _enclaveAddress The address of the enclave to revive.
     * @dev Caller must be the owner of the enclave node.
     */
    function reviveSecretStore(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stakeAmount
    ) external onlyTeeManager {
        _reviveSecretStore(_enclaveAddress, _env, _stakeAmount);
    }

    /**
     * @notice Adds stake to an enclave node.
     * @param _enclaveAddress The address of the enclave to add stake to.
     * @dev Caller must be the owner of the enclave node.
     */
    function addSecretStoreStake(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stake
    ) external onlyTeeManager {
        _upsertTreeNode(_enclaveAddress, _env, _stake);
    }

    /**
     * @notice Removes stake from an enclave node.
     * @param _enclaveAddress The address of the enclave to remove stake from.
     * @dev Caller must be the owner of the enclave node.
     */
    function removeSecretStoreStake(
        address _enclaveAddress
    ) external view onlyTeeManager {
        _removeSecretStoreStake(_enclaveAddress);
    }

    function upsertTreeNode(
        uint8 _env,
        address _enclaveAddress,
        uint256 _stakeAmount
    ) external onlyTeeManager {
        _upsertTreeNode(_enclaveAddress, _env, _stakeAmount);
    }

    function deleteTreeNodeIfPresent(
        uint8 _env,
        address _enclaveAddress
    ) external onlyTeeManager {
        _deleteIfPresent(_env, _enclaveAddress);
    }

    //-------------------------------- external functions end ----------------------------------//

    //------------------------------- TeeManagerRole functions end --------------------------------------//

    //----------------------------- SecretManagerRole functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _selectNonAssignedSecretStore(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit,
        address[] memory _selectedStoresToIgnore
    ) internal returns (SecretManager.SelectedEnclave[] memory) {
        // remove the already selected stores from the tree so they are not selected back again as duplicates
        _deleteTreeNodes(_env, _selectedStoresToIgnore);
        SecretManager.SelectedEnclave[] memory  selectedStores = _selectStores(_env, _noOfNodesToSelect, _sizeLimit);
        // add back the removed stores to the tree
        _addTreeNodes(_env, _selectedStoresToIgnore);

        return selectedStores;
    }

    function _selectStores(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) internal returns (SecretManager.SelectedEnclave[] memory) {
        address[] memory selectedNodes = _selectNodes(_env, _noOfNodesToSelect);

        uint len = selectedNodes.length;
        SecretManager.SelectedEnclave[] memory  selectedEnclaves = new SecretManager.SelectedEnclave[](len);
        for (uint256 index = 0; index < len; index++) {
            address enclaveAddress = selectedNodes[index];
            secretStores[enclaveAddress].storageOccupied += _sizeLimit;

            SecretManager.SelectedEnclave memory selectedEnclave;
            selectedEnclave.enclaveAddress = enclaveAddress;
            selectedEnclave.selectTimestamp = block.timestamp;
            selectedEnclaves[index] = selectedEnclave;

            // TODO: need to have some buffer space for each enclave
            if (
                secretStores[enclaveAddress].storageOccupied >= 
                (secretStores[enclaveAddress].storageCapacity - SECRET_MANAGER.GLOBAL_MAX_STORE_SIZE())
            )
                _deleteIfPresent(_env, enclaveAddress);
        }
        return selectedEnclaves;
    }

    function _selectNodes(
        uint8 _env,
        uint256 _noOfNodesToSelect
    ) internal view returns (address[] memory selectedNodes) {
        uint256 randomizer = uint256(keccak256(abi.encode(blockhash(block.number - 1), block.timestamp)));
        selectedNodes = _selectN(_env, randomizer, _noOfNodesToSelect);
    }

    function _deleteTreeNodes(
        uint8 _env,
        address[] memory _enclaveAddresses
    ) internal {
        uint256 len = _enclaveAddresses.length;
        for (uint256 index = 0; index < len; index++) {
            _deleteIfPresent(_env, _enclaveAddresses[index]);
        }
    }

    function _addTreeNodes(
        uint8 _env,
        address[] memory _enclaveAddresses
    ) internal {
        uint256[] memory stakeAmounts = TEE_MANAGER.getTeeNodesStake(_enclaveAddresses);
        uint256 len = _enclaveAddresses.length;
        for (uint256 index = 0; index < len; index++) {
            _insert_unchecked(_env, _enclaveAddresses[index], uint64(stakeAmounts[index] / STAKE_ADJUSTMENT_FACTOR));
        }
    }

    function _slashStore(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) internal {
        uint256 lastAliveTimestamp = secretStores[_enclaveAddress].lastAliveTimestamp;
        uint256 deadTimestamp = secretStores[_enclaveAddress].deadTimestamp;
        uint256 lastCheckTimestamp = (lastAliveTimestamp > deadTimestamp) ? lastAliveTimestamp : deadTimestamp;
        uint256 missedEpochsCount = ((_currentCheckTimestamp - lastAliveTimestamp) / _markAliveTimeout ) - 
            ((lastCheckTimestamp - lastAliveTimestamp) / _markAliveTimeout);

        if(missedEpochsCount > 0)
            TEE_MANAGER.slashStore(_enclaveAddress, missedEpochsCount, _recipient);
    }

    function _releaseStore(
        address _enclaveAddress,
        uint256 _secretSize
    ) internal {
        secretStores[_enclaveAddress].storageOccupied -= _secretSize;
        TEE_MANAGER.updateTreeState(_enclaveAddress);
    }

    function _removeStoreSecretId(
        address _enclaveAddress,
        uint256 _secretId
    ) internal {
        uint256 len = secretStores[_enclaveAddress].ackSecretIds.length;
        for (uint256 index = 0; index < len; index++) {
            if(secretStores[_enclaveAddress].ackSecretIds[index] == _secretId) {
                if(index != len - 1)
                    secretStores[_enclaveAddress].ackSecretIds[index] = secretStores[_enclaveAddress].ackSecretIds[len - 1];
                secretStores[_enclaveAddress].ackSecretIds.pop();
                break;
            }
        }
    }

    function _markAliveUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) internal {
        _slashStore(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
        TEE_MANAGER.updateTreeState(_enclaveAddress);
        secretStores[_enclaveAddress].lastAliveTimestamp = _currentCheckTimestamp;
    }

    function _markDeadUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        uint256 _storageOccupied,
        address _recipient
    ) internal {
        _slashStore(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
        secretStores[_enclaveAddress].deadTimestamp = _currentCheckTimestamp;

        _releaseStore(_enclaveAddress, _storageOccupied);
        delete secretStores[_enclaveAddress].ackSecretIds;
    }

    function _renounceSecretsPreUpdate(
        address _enclaveAddress,
        uint256 _markAliveTimeout,
        address _recipient
    ) internal {
        _slashStore(_enclaveAddress, block.timestamp, _markAliveTimeout, _recipient);
        secretStores[_enclaveAddress].lastAliveTimestamp = block.timestamp;
    }

    function _renounceSecretsPostUpdate(
        address _enclaveAddress,
        uint256 _storageOccupied
    ) internal {
        secretStores[_enclaveAddress].storageOccupied -= _storageOccupied;
        delete secretStores[_enclaveAddress].ackSecretIds;
    }

    function _secretTerminationUpdate(
        address _enclaveAddress,
        uint256 _secretSize,
        uint256 _secretId
    ) internal {
        _releaseStore(_enclaveAddress, _secretSize);
        _removeStoreSecretId(_enclaveAddress, _secretId);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function selectNonAssignedSecretStore(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit,
        address[] memory _selectedStoresToIgnore
    ) external onlySecretManager isValidEnv(_env) returns (SecretManager.SelectedEnclave[] memory) {
        return _selectNonAssignedSecretStore(_env, _noOfNodesToSelect, _sizeLimit, _selectedStoresToIgnore);
    }

    function selectStores(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) external onlySecretManager isValidEnv(_env) returns (SecretManager.SelectedEnclave[] memory) {
        return _selectStores(_env, _noOfNodesToSelect, _sizeLimit);
    }

    function releaseStore(
        address _enclaveAddress,
        uint256 _secretSize
    ) external onlySecretManager {
        _releaseStore(_enclaveAddress, _secretSize);
    }

    function markAliveUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) external onlySecretManager {
        _markAliveUpdate(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
    }

    function markDeadUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        uint256 _storageOccupied,
        address _recipient
    ) external onlySecretManager {
        _markDeadUpdate(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _storageOccupied, _recipient);
    }

    function secretTerminationUpdate(
        address _enclaveAddress,
        uint256 _secretSize,
        uint256 _secretId
    ) external onlySecretManager {
        _secretTerminationUpdate(_enclaveAddress, _secretSize, _secretId);
    }

    function addAckSecretIdToStore(
        address _enclaveAddress,
        uint256 _ackSecretId
    ) external onlySecretManager {
        secretStores[_enclaveAddress].ackSecretIds.push(_ackSecretId);
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

    //---------------------------------- external functions end ------------------------------------//

    //------------------------------ SecretManagerRole functions end ----------------------------------//

}
