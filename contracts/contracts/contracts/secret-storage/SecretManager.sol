// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./TeeManager.sol";
import "./Executors.sol";
import "./SecretStore.sol";

/**
 * @title SecretManager Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract SecretManager is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Thrown when the provided ERC20 token address is zero.
    error SecretManagerZeroAddressUsdcToken();

    /**
     * @dev Initializes the logic contract without any admins, safeguarding against takeover.
     * @param attestationVerifier The attestation verifier contract.
     * @param maxAge Maximum age for attestations.
     * @param _token The ERC20 token used for staking.
     * @param _minStakeAmount Minimum stake amount required.
     * @param _slashPercentInBips Slashing percentage in basis points.
     * @param _slashMaxBips Maximum basis points for slashing.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IERC20 _usdcToken,
        uint256 _noOfNodesToSelect,
        uint256 _globalMaxStoreSize,
        uint256 _globalMinStoreDuration,
        uint256 _globalMaxStoreDuration,
        uint256 _acknowledgementTimeout,
        uint256 _markAliveTimeout,
        uint256 _secretStoreFeeRate,
        address _stakingPaymentPool,
        TeeManager _teeManager,
        Executors _executors,
        SecretStore _secretStore
    ) {
        _disableInitializers();

        if (address(_usdcToken) == address(0)) revert SecretManagerZeroAddressUsdcToken();

        USDC_TOKEN = _usdcToken;
        NO_OF_NODES_TO_SELECT = _noOfNodesToSelect;

        // TODO: add checks
        GLOBAL_MAX_STORE_SIZE = _globalMaxStoreSize;
        GLOBAL_MIN_STORE_DURATION = _globalMinStoreDuration;
        GLOBAL_MAX_STORE_DURATION = _globalMaxStoreDuration;
        // TODO: endTimestamp should be greater than acknowledge timeout
        ACKNOWLEDGEMENT_TIMEOUT = _acknowledgementTimeout;
        MARK_ALIVE_TIMEOUT = _markAliveTimeout;
        SECRET_STORE_FEE_RATE = _secretStoreFeeRate;
        STAKING_PAYMENT_POOL = _stakingPaymentPool;
        TEE_MANAGER = _teeManager;
        EXECUTORS = _executors;
        SECRET_STORE = _secretStore;
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
    error SecretManagerZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin.
     * @param _admin The address of the admin.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert SecretManagerZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable USDC_TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable NO_OF_NODES_TO_SELECT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MAX_STORE_SIZE;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MIN_STORE_DURATION;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MAX_STORE_DURATION;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable ACKNOWLEDGEMENT_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MARK_ALIVE_TIMEOUT;

    /// @notice Fee rate per unit size per second per secret store.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SECRET_STORE_FEE_RATE;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable STAKING_PAYMENT_POOL;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    TeeManager public immutable TEE_MANAGER;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    Executors public immutable EXECUTORS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    SecretStore public immutable SECRET_STORE;

    //------------------------------------ SecretManager start -----------------------------------//

    modifier isValidSecretOwner(uint256 _secretId) {
        if(userStorage[_secretId].owner != _msgSender())
            revert SecretManagerInvalidSecretOwner();
        _;
    }

    modifier onlySecretStore() {
        if (_msgSender() != address(SECRET_STORE))
            revert SecretManagerCallerIsNotSecretStore();
        _;
    }

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.SecretManager"),
                keccak256("1")
            )
        );

    bytes32 private constant ACKNOWLEDGE_TYPEHASH =
        keccak256("Acknowledge(uint256 secretId,uint256 signTimestamp)");

    bytes32 private constant ALIVE_TYPEHASH =
        keccak256("Alive(uint256 signTimestamp)");

    /// @notice Thrown when the signature timestamp has expired.
    error SecretManagerSignatureTooOld();

    struct SelectedEnclave {
        address enclaveAddress;
        bool hasAcknowledgedStore;
        uint256 selectTimestamp;
        uint256 replacedAckTimestamp;  // only reqd for replaced stores(when a previous store is marked dead and replaced)
    }

    struct UserStorage {
        uint8 env;
        address owner;
        uint256 sizeLimit;
        uint256 usdcDeposit;
        uint256 startTimestamp;
        uint256 endTimestamp;
        uint256 ackTimestamp;   // stores the time when the last node sends ack
        address[] allowedAddresses;
        SelectedEnclave[] selectedEnclaves;
    }

    // secretId => user store data
    mapping(uint256 => UserStorage) public userStorage;

    uint256 public secretId;

    event SecretCreated(
        uint256 indexed secretId,
        address indexed owner,
        uint256 sizeLimit,
        uint256 endTimestamp,
        uint256 usdcDeposit,
        address[] selectedEnclaves
    );

    event SecretStoreAcknowledgementSuccess(
        uint256 indexed secretId,
        address indexed enclaveAddress
    );

    event SecretStoreAcknowledgementFailed(
        uint256 indexed secretId
    );

    event SecretStoreReplaced(
        uint256 indexed secretId,
        address indexed prevEnclaveAddress,
        address indexed newEnclaveAddress,
        bool isMarkedDead   // true if event is emitted due to mark dead, false if emitted due to replaced store ack fail
    );

    event SecretStoreAlive(
        address indexed enclaveAddress
    );

    event SecretReplicationReduced(
        uint256 indexed secretId,
        uint256 replicationCount
    );

    event SecretEndTimestampUpdated(
        uint256 indexed secretId,
        uint256 endTimestamp
    );

    event SecretTerminated(
        uint256 indexed secretId,
        uint256 timestamp
    );

    event SecretRemoved(
        uint256 indexed secretId
    );

    error SecretManagerCallerIsNotSecretStore();
    error SecretManagerInsufficientUsdcDeposit();
    error SecretManagerInvalidSizeLimit();
    error SecretManagerInvalidEndTimestamp();
    error SecretManagerUnavailableResources();
    error SecretManagerAcknowledgementTimeOver();
    error SecretManagerAcknowledgementTimeoutPending(address enclaveAddress);
    error SecretManagerAcknowledgedAlready();
    error SecretManagerUnacknowledged();
    error SecretManagerNodeIsDraining();
    error SecretManagerEnclaveNotFound();
    error SecretManagerStoreIsAlive();
    error SecretManagerInvalidSecretOwner();
    error SecretManagerAlreadyTerminated();
    error SecretManagerCantAckWhileDraining();
    error SecretManagerTerminationPending();
    error SecretManagerAlreadyAcknowledged();
    error SecretManagerUserNotAllowed();
    error SecretManagerInvalidSecret();
    error SecretManagerStoreNotDraining();

    //-------------------------------- internal functions start ----------------------------------//

    function _createSecret(
        uint8 _env,
        uint256 _sizeLimit,
        uint256 _endTimestamp,
        uint256 _usdcDeposit,
        address[] memory _allowedAddresses,
        address _owner
    ) internal {
        if(_sizeLimit == 0 || _sizeLimit > GLOBAL_MAX_STORE_SIZE)
            revert SecretManagerInvalidSizeLimit();

        if ((_endTimestamp < block.timestamp + GLOBAL_MIN_STORE_DURATION) || (_endTimestamp > block.timestamp + GLOBAL_MAX_STORE_DURATION)) 
            revert SecretManagerInvalidEndTimestamp();

        uint256 minUsdcDeposit = (_endTimestamp - block.timestamp) * _sizeLimit * SECRET_STORE_FEE_RATE * NO_OF_NODES_TO_SELECT;
        _checkUsdcDeposit(_usdcDeposit, minUsdcDeposit);

        USDC_TOKEN.safeTransferFrom(_owner, address(this), _usdcDeposit);

        SelectedEnclave[] memory selectedEnclaves = SECRET_STORE.selectStores(_env, NO_OF_NODES_TO_SELECT, _sizeLimit);
        if (selectedEnclaves.length < NO_OF_NODES_TO_SELECT)
            revert SecretManagerUnavailableResources();

        uint256 id = ++secretId;
        userStorage[id].env = _env;
        userStorage[id].owner = _owner;
        userStorage[id].sizeLimit = _sizeLimit;
        userStorage[id].usdcDeposit = _usdcDeposit;
        userStorage[id].startTimestamp = block.timestamp;
        userStorage[id].endTimestamp = _endTimestamp;
        userStorage[id].allowedAddresses = _allowedAddresses;

        uint len = selectedEnclaves.length;
        address[] memory enclaveAddresses = new address[](len);
        for (uint256 index = 0; index < len; index++) {
            // cannot allocate memory array directly to storage var
            userStorage[id].selectedEnclaves.push(selectedEnclaves[index]);
            enclaveAddresses[index] = selectedEnclaves[index].enclaveAddress;
        }

        emit SecretCreated(secretId, _owner, _sizeLimit, _endTimestamp, _usdcDeposit, enclaveAddresses);
    }

    function _checkUsdcDeposit(
        uint256 _usdcDeposit,
        uint256 _minUsdcDeposit
    ) internal pure {
        if(_usdcDeposit < _minUsdcDeposit)
            revert SecretManagerInsufficientUsdcDeposit();
    }

    function _acknowledgeStore(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal {
        if(_signTimestamp > userStorage[_secretId].endTimestamp)
            revert SecretManagerAlreadyTerminated();

        address enclaveAddress = _verifyAcknowledgementSign(_secretId, _signTimestamp, _signature);
        if(TEE_MANAGER.getDrainingStatus(enclaveAddress))
            revert SecretManagerCantAckWhileDraining();

        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, enclaveAddress);
        if(block.timestamp > userStorage[_secretId].selectedEnclaves[enclaveIndex].selectTimestamp + ACKNOWLEDGEMENT_TIMEOUT)
            revert SecretManagerAcknowledgementTimeOver();

        if(userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore)
            revert SecretManagerAlreadyAcknowledged();

        userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore = true;

        // Add secretId to the ackSecretIds list only when the secret has been acknowledged by the first set of selected stores
        if(_isReplacedStore(_secretId, enclaveIndex)) {
            userStorage[_secretId].selectedEnclaves[enclaveIndex].replacedAckTimestamp = _signTimestamp;
            SECRET_STORE.addAckSecretIdToStore(enclaveAddress, _secretId);
        }
        else if(_checkIfSecretAcknowledged(_secretId)) {
            userStorage[_secretId].ackTimestamp = _signTimestamp;
            uint256 len = userStorage[_secretId].selectedEnclaves.length;
            for (uint256 index = 0; index < len; index++) {
                SECRET_STORE.addAckSecretIdToStore(userStorage[_secretId].selectedEnclaves[index].enclaveAddress, _secretId);
            }
        }

        emit SecretStoreAcknowledgementSuccess(_secretId, enclaveAddress);
    }

    function _isReplacedStore(
        uint256 _secretId,
        uint256 _enclaveIndex
    ) internal view returns (bool) {
        return userStorage[_secretId].startTimestamp != userStorage[_secretId].selectedEnclaves[_enclaveIndex].selectTimestamp;
    }

    function _verifyAcknowledgementSign(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view returns(address signer) {
        _checkSignValidity(_signTimestamp);

        bytes32 hashStruct = keccak256(abi.encode(ACKNOWLEDGE_TYPEHASH, _secretId, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        signer = digest.recover(_signature);

        TEE_MANAGER.allowOnlyVerified(signer);
    }

    function _checkSignValidity(uint256 _signTimestamp) internal view {
        if (block.timestamp > _signTimestamp + TEE_MANAGER.ATTESTATION_MAX_AGE())
            revert SecretManagerSignatureTooOld();
    }

    function _getSelectedEnclaveIndex(
        uint256 _secretId,
        address _enclaveAddress
    ) internal view returns (uint256) {
        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        for (uint256 index = 0; index < len; index++) {
            if(userStorage[_secretId].selectedEnclaves[index].enclaveAddress == _enclaveAddress)
                return index;
        }
        revert SecretManagerEnclaveNotFound();
    }

    function _acknowledgeStoreFailed(
        uint256 _secretId
    ) internal {
        bool ackFailed;
        bool reselectedAckFailed;
        for (uint256 index = 0; index < userStorage[_secretId].selectedEnclaves.length; ) {
            UserStorage memory userStoreData = userStorage[_secretId];
            address enclaveAddress = userStoreData.selectedEnclaves[index].enclaveAddress;

            // case for replaced stores(after mark dead txn)
            if (_isReplacedStore(_secretId, index)) {
                if (
                    !userStoreData.selectedEnclaves[index].hasAcknowledgedStore &&
                    block.timestamp > userStoreData.selectedEnclaves[index].selectTimestamp + ACKNOWLEDGEMENT_TIMEOUT
                ) {
                    SECRET_STORE.releaseStore(enclaveAddress, userStoreData.sizeLimit);

                    reselectedAckFailed = true;
                    bool isArrayLenReduced = _replaceStore(_secretId, enclaveAddress, index, false);
                    if(isArrayLenReduced)
                        continue;
                }
            } else {
                if(block.timestamp <= userStoreData.selectedEnclaves[index].selectTimestamp + ACKNOWLEDGEMENT_TIMEOUT)
                    revert SecretManagerAcknowledgementTimeoutPending(enclaveAddress);

                if (!userStoreData.selectedEnclaves[index].hasAcknowledgedStore)
                    ackFailed = true;

                SECRET_STORE.releaseStore(enclaveAddress, userStoreData.sizeLimit);
            }
            ++index;
        }

        if(!reselectedAckFailed && !ackFailed)
            revert SecretManagerAcknowledgedAlready();

        if(ackFailed) {
            address owner = userStorage[_secretId].owner;
            uint256 usdcDeposit = userStorage[_secretId].usdcDeposit;
            delete userStorage[_secretId];
            USDC_TOKEN.safeTransfer(owner, usdcDeposit);

            emit SecretStoreAcknowledgementFailed(_secretId);
        }
    }

    function _replaceStore(
        uint256 _secretId,
        address _enclaveAddress,
        uint256 _enclaveIndex,
        bool _isMarkedDead  // true if called due to mark dead, false if called due to replaced store ack fail
    ) internal returns (bool isArrayLenReduced) {
        // case for when the termination condition is reached, we won't select any new enclave
        if(block.timestamp > userStorage[_secretId].endTimestamp) {
            isArrayLenReduced = true;
            _removeSelectedEnclave(_secretId, _enclaveIndex);
            if(userStorage[_secretId].selectedEnclaves.length == 0)
                _refundExcessDepositAndRemoveSecret(_secretId);
        }
        // case for when a newly selected enclave will replace the dead enclave
        else {
            address[] memory selectedStores = _getSelectedStoresExceptReplaced(_secretId, _enclaveIndex);
            SelectedEnclave[] memory selectedEnclaves = SECRET_STORE.selectNonAssignedSecretStore(
                userStorage[_secretId].env,
                1,
                userStorage[_secretId].sizeLimit,
                selectedStores
            );

            // TODO: what if replication reaches 0? Need to notify the user on UI to terminate the secret if replication factor reduces.
            // case for when a new enclave can't be selected as they all are already occupied to their max storage capacity
            if (selectedEnclaves.length == 0) {
                isArrayLenReduced = true;
                _removeSelectedEnclave(_secretId, _enclaveIndex);
                emit SecretReplicationReduced(_secretId, userStorage[_secretId].selectedEnclaves.length);
            }
            // case for when a newly selected enclave will replace the dead enclave
            else {
                userStorage[_secretId].selectedEnclaves[_enclaveIndex] = SelectedEnclave({
                    enclaveAddress: selectedEnclaves[0].enclaveAddress,
                    hasAcknowledgedStore: false,
                    selectTimestamp: selectedEnclaves[0].selectTimestamp,
                    replacedAckTimestamp: 0
                });
            }
            emit SecretStoreReplaced(
                _secretId,
                _enclaveAddress,
                selectedEnclaves.length != 0 ? selectedEnclaves[0].enclaveAddress : address(0),
                _isMarkedDead
            );
        }
    }

    function _getSelectedStoresExceptReplaced(
        uint256 _secretId,
        uint256 _enclaveIndex
    ) internal view returns (address[] memory) {
        uint256 key;
        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        address[] memory stores = new address[](len - 1);
        for (uint256 index = 0; index < len; index++) {
            if(index != _enclaveIndex)
                stores[key++] = userStorage[_secretId].selectedEnclaves[index].enclaveAddress;
        }
        return stores;
    }

    function _markStoreAlive(
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal {
        address enclaveAddress = _verifyStoreAliveSign(_signTimestamp, _signature);
        if(TEE_MANAGER.getDrainingStatus(enclaveAddress))
            revert SecretManagerNodeIsDraining();
        if(_signTimestamp <= SECRET_STORE.getSecretStoreDeadTimestamp(enclaveAddress))
            revert SecretManagerSignatureTooOld();

        address owner = TEE_MANAGER.getTeeNodeOwner(enclaveAddress);
        uint256 lastAliveTimestamp = SECRET_STORE.getSecretStoreLastAliveTimestamp(enclaveAddress);
        SECRET_STORE.markAliveUpdate(enclaveAddress, _signTimestamp, MARK_ALIVE_TIMEOUT, STAKING_PAYMENT_POOL);

        uint256[] memory storeAckSecretIds = SECRET_STORE.getStoreAckSecretIds(enclaveAddress);
        uint256 len = storeAckSecretIds.length;
        uint256 storageTimeUsage;
        for (uint256 index = 0; index < len; index++) {
            uint256 secId = storeAckSecretIds[index];
            uint256 sizeLimit = userStorage[secId].sizeLimit;
            storageTimeUsage += (_markEnclaveAlive(secId, enclaveAddress, _signTimestamp, lastAliveTimestamp, sizeLimit) * sizeLimit);
        }

        uint256 usdcPayment = storageTimeUsage * SECRET_STORE_FEE_RATE;
        USDC_TOKEN.safeTransfer(owner, usdcPayment);

        emit SecretStoreAlive(enclaveAddress);
    }

    function _markEnclaveAlive(
        uint256 _secretId,
        address _enclaveAddress,
        uint256 _signTimestamp,
        uint256 _lastAliveTimestamp,
        uint256 _sizeLimit
    ) internal returns (uint256 /* storageTimeDuration */) {
        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, _enclaveAddress);

        uint256 ackTimestamp = _getSecretStoreAckTimestamp(_secretId, enclaveIndex);
        uint256 startTimestamp = ackTimestamp > _lastAliveTimestamp ? ackTimestamp : _lastAliveTimestamp;
        uint256 endTimestamp = userStorage[_secretId].endTimestamp;

        // secret terminated
        if(_signTimestamp > endTimestamp) {
            SECRET_STORE.secretTerminationUpdate(_enclaveAddress, _sizeLimit, _secretId);

            _updateUsdcDepositPostPayment(_secretId, ackTimestamp, endTimestamp, _signTimestamp);

            _removeSelectedEnclave(_secretId, enclaveIndex);

            if(userStorage[_secretId].selectedEnclaves.length == 0)
                _refundExcessDepositAndRemoveSecret(_secretId);
        }
        else
            endTimestamp = _signTimestamp;

        return (endTimestamp - startTimestamp);
    }

    function _verifyStoreAliveSign(
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view returns(address signer) {
        _checkSignValidity(_signTimestamp);

        bytes32 hashStruct = keccak256(abi.encode(ALIVE_TYPEHASH, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        signer = digest.recover(_signature);

        TEE_MANAGER.allowOnlyVerified(signer);
    }

    // TODO: reward the sender
    function _markStoreDead(
        address _enclaveAddress
    ) internal {
        if(TEE_MANAGER.getDrainingStatus(_enclaveAddress))
            revert SecretManagerNodeIsDraining();
        uint256 lastAliveTimestamp = SECRET_STORE.getSecretStoreLastAliveTimestamp(_enclaveAddress);
        if(block.timestamp <= lastAliveTimestamp + MARK_ALIVE_TIMEOUT)
            revert SecretManagerStoreIsAlive();

        uint256[] memory storeAckSecretIds = SECRET_STORE.getStoreAckSecretIds(_enclaveAddress);
        uint256 len = storeAckSecretIds.length;
        uint256 occupiedStorage;
        for (uint256 index = 0; index < len; index++) {
            uint256 secId = storeAckSecretIds[index];
            occupiedStorage += userStorage[secId].sizeLimit;
            _markEnclaveDead(secId, _enclaveAddress, lastAliveTimestamp);
        }

        SECRET_STORE.markDeadUpdate(_enclaveAddress, block.timestamp, MARK_ALIVE_TIMEOUT, occupiedStorage, STAKING_PAYMENT_POOL);
    }

    function _markEnclaveDead(
        uint256 _secretId,
        address _enclaveAddress,
        uint256 _lastAliveTimestamp
    ) internal {
        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, _enclaveAddress);
        // if(!userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore || userStorage[_secretId].ackTimestamp == 0)
        //     return;

        uint256 ackTimestamp = _getSecretStoreAckTimestamp(_secretId, enclaveIndex);
        uint256 endTimestamp = userStorage[_secretId].endTimestamp;
        _updateUsdcDepositPostPayment(_secretId, ackTimestamp, endTimestamp, _lastAliveTimestamp);

        _replaceStore(_secretId, _enclaveAddress, enclaveIndex, true);
    }

    function _renounceSecrets(
        address _enclaveAddress,
        address _owner,
        uint256[] memory _storeAckSecretIds,
        uint256 _lastAliveTimestamp
    ) internal returns (uint256 occupiedStorage) {
        uint256 len = _storeAckSecretIds.length;
        uint256 storageTimeUsage;
        for (uint256 index = 0; index < len; index++) {
            uint256 secId = _storeAckSecretIds[index];
            uint256 sizeLimit = userStorage[secId].sizeLimit;
            occupiedStorage += sizeLimit;

            storageTimeUsage += (_renounceSecret(_enclaveAddress, secId, _lastAliveTimestamp) * sizeLimit);
        }

        uint256 usdcPayment = storageTimeUsage * SECRET_STORE_FEE_RATE;
        USDC_TOKEN.safeTransfer(_owner, usdcPayment);
    }

    function _renounceSecret(
        address _enclaveAddress,
        uint256 _secretId,
        uint256 _lastAliveTimestamp
    ) internal returns (uint256 /* storageTimeDuration */) {
        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, _enclaveAddress);

        uint256 ackTimestamp = _getSecretStoreAckTimestamp(_secretId, enclaveIndex);

        uint256 startTimestamp = ackTimestamp > _lastAliveTimestamp ? ackTimestamp : _lastAliveTimestamp;
        uint256 endTimestamp = userStorage[_secretId].endTimestamp;

        _updateUsdcDepositPostPayment(_secretId, ackTimestamp, endTimestamp, block.timestamp);

        // secret terminated
        if(block.timestamp > endTimestamp) {
            _removeSelectedEnclave(_secretId, enclaveIndex);

            if(userStorage[_secretId].selectedEnclaves.length == 0)
                _refundExcessDepositAndRemoveSecret(_secretId);
        }
        else {
            endTimestamp = block.timestamp;
            _replaceStore(_secretId, _enclaveAddress, enclaveIndex, true);
        }

        return (endTimestamp - startTimestamp);
    }

    function _getSecretStoreAckTimestamp(
        uint256 _secretId,
        uint256 _enclaveIndex
    ) internal view returns (uint256 ackTimestamp) {
        if(_isReplacedStore(_secretId, _enclaveIndex))
            ackTimestamp = userStorage[_secretId].selectedEnclaves[_enclaveIndex].replacedAckTimestamp;
        else
            ackTimestamp = userStorage[_secretId].ackTimestamp;
    }

    /**
     * @dev It updates usdc deposit based on the payment to the selected store.
     *      It is executed when - 
     *      (1) alive check is submitted for terminated secretId 
                (duration considered for the reward = min(lastAliveTimestamp, endTimestamp) - ackTimemstamp)
     *      (2) dead check
                (duration considered for the reward = lastAliveTimestamp - ackTimemstamp)
     *      (3) remove secret is called post termination
                (duration considered for the reward = lastAliveTimestamp - ackTimemstamp)
     */
    function _updateUsdcDepositPostPayment(
        uint256 _secretId,
        uint256 _ackTimestamp,
        uint256 _endTimestamp,
        uint256 _latestAliveTimestamp
    ) internal {
        if(_latestAliveTimestamp < _endTimestamp)
            _endTimestamp = _latestAliveTimestamp;

        if(_endTimestamp <= _ackTimestamp)
            return;

        uint256 storePayment = (_endTimestamp - _ackTimestamp) * userStorage[_secretId].sizeLimit * SECRET_STORE_FEE_RATE;
        userStorage[_secretId].usdcDeposit -= storePayment;
    }

    function _removeSelectedEnclave(
        uint256 _secretId,
        uint256 _index
    ) internal {
        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        if(_index != len - 1)
            userStorage[_secretId].selectedEnclaves[_index] = userStorage[_secretId].selectedEnclaves[len - 1];
        userStorage[_secretId].selectedEnclaves.pop();
    }

    function _refundExcessDepositAndRemoveSecret(
        uint256 _secretId
    ) internal {
        address owner = userStorage[_secretId].owner;
        uint256 remainingDeposit = userStorage[_secretId].usdcDeposit;
        delete userStorage[_secretId];
        USDC_TOKEN.safeTransfer(owner, remainingDeposit);
    }

    function _updateSecretEndTimestamp(
        uint256 _secretId,
        uint256 _endTimestamp,
        uint256 _usdcDeposit,
        address _owner
    ) internal {
        if(_endTimestamp < block.timestamp)
            revert SecretManagerInvalidEndTimestamp();

        uint256 currentEndTimestamp = userStorage[_secretId].endTimestamp;
        if(block.timestamp > currentEndTimestamp)
            revert SecretManagerAlreadyTerminated();

        if(!_checkIfSecretAcknowledged(_secretId))
            revert SecretManagerUnacknowledged();

        if(_endTimestamp > currentEndTimestamp) {
            USDC_TOKEN.safeTransferFrom(_owner, address(this), _usdcDeposit);
            userStorage[_secretId].usdcDeposit += _usdcDeposit;

            uint256 minUsdcDeposit = (_endTimestamp - userStorage[_secretId].startTimestamp) * userStorage[_secretId].sizeLimit * SECRET_STORE_FEE_RATE * NO_OF_NODES_TO_SELECT;
            _checkUsdcDeposit(userStorage[_secretId].usdcDeposit, minUsdcDeposit);
        }
        else {
            uint256 removedDuration = currentEndTimestamp - _endTimestamp;
            uint256 usdcRefund = removedDuration * userStorage[_secretId].sizeLimit * SECRET_STORE_FEE_RATE * NO_OF_NODES_TO_SELECT;
            
            userStorage[_secretId].usdcDeposit -= usdcRefund;
            USDC_TOKEN.safeTransfer(_owner, usdcRefund);
        }

        userStorage[_secretId].endTimestamp = _endTimestamp;

        emit SecretEndTimestampUpdated(_secretId, _endTimestamp);
    }

    /**
     * @dev Checks if the secret has been acknowledged by the first set of selected enclaves.
     *      Replacement store selected post slashing of the previous store, isn't taken into account.
     */
    function _checkIfSecretAcknowledged(
        uint256 _secretId
    ) internal view returns (bool) {
        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        for (uint256 index = 0; index < len; index++) {
            if(!_isReplacedStore(_secretId, index) && !userStorage[_secretId].selectedEnclaves[index].hasAcknowledgedStore)
                return false;
        }
        return true;
    }

    function _terminateSecret(
        uint256 _secretId
    ) internal {
        if(block.timestamp >= userStorage[_secretId].endTimestamp)
            revert SecretManagerAlreadyTerminated();

        userStorage[_secretId].endTimestamp = block.timestamp;

        emit SecretTerminated(_secretId, block.timestamp);
    }

    function _removeSecret(
        uint256 _secretId
    ) internal {
        if(userStorage[_secretId].owner == address(0))
            revert SecretManagerInvalidSecret();
        if(block.timestamp <= userStorage[_secretId].endTimestamp + MARK_ALIVE_TIMEOUT)
            revert SecretManagerTerminationPending();

        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        for (uint256 index = 0; index < len; index++) {
            address enclaveAddress = userStorage[_secretId].selectedEnclaves[index].enclaveAddress;
            uint256 ackTimestamp = _getSecretStoreAckTimestamp(_secretId, index);
            uint256 endTimestamp = userStorage[_secretId].endTimestamp;
            uint256 lastAliveTimestamp = SECRET_STORE.getSecretStoreLastAliveTimestamp(enclaveAddress);
            _updateUsdcDepositPostPayment(_secretId, ackTimestamp, endTimestamp, lastAliveTimestamp);

            SECRET_STORE.secretTerminationUpdate(enclaveAddress, userStorage[_secretId].sizeLimit, _secretId);
        }
        _refundExcessDepositAndRemoveSecret(_secretId);

        emit SecretRemoved(_secretId);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //------------------------------- external functions start ----------------------------------//

    function createSecret(
        uint8 _env,
        uint256 _sizeLimit,
        uint256 _endTimestamp,
        uint256 _usdcDeposit,
        address[] memory _allowedAddresses
    ) external {
        _createSecret(_env, _sizeLimit, _endTimestamp, _usdcDeposit, _allowedAddresses, _msgSender());
    }

    function acknowledgeStore(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) external {
        _acknowledgeStore(_secretId, _signTimestamp, _signature);
    }

    function acknowledgeStoreFailed(
        uint256 _secretId
    ) external {
        _acknowledgeStoreFailed(_secretId);
    }

    function markStoreAlive(
        uint256 _signTimestamp,
        bytes memory _signature
    ) external {
        _markStoreAlive(_signTimestamp, _signature);
    }

    function markStoreDead(
        address _enclaveAddress
    ) external {
        _markStoreDead(_enclaveAddress);
    }

    function updateSecretEndTimestamp(
        uint256 _secretId,
        uint256 _endTimestamp,
        uint256 _usdcDeposit
    ) external isValidSecretOwner(_secretId) {
        _updateSecretEndTimestamp(_secretId, _endTimestamp, _usdcDeposit, _msgSender());
    }

    function renounceSecrets(
        address _enclaveAddress,
        address _owner,
        uint256[] memory _storeAckSecretIds,
        uint256 _lastAliveTimestamp
    ) external onlySecretStore returns (uint256 /* occupiedStorage */) {
        return _renounceSecrets(_enclaveAddress, _owner, _storeAckSecretIds, _lastAliveTimestamp);
    }

    function terminateSecret(
        uint256 _secretId
    ) external isValidSecretOwner(_secretId) {
        _terminateSecret(_secretId);
    }

    function removeSecret(
        uint256 _secretId
    ) external {
        _removeSecret(_secretId);
    }

    function getSelectedEnclaves(uint256 _secretId) external view returns (SelectedEnclave[] memory) {
        return userStorage[_secretId].selectedEnclaves;
    }

    function getCurrentConfirmedUsdcDeposit(
        uint256 _secretId
    ) external view returns (uint256) {
        uint256 usdcDeposit = userStorage[_secretId].usdcDeposit;
        SelectedEnclave[] memory selectedEnclaves = userStorage[_secretId].selectedEnclaves;
        uint256 len = selectedEnclaves.length;
        for (uint256 index = 0; index < len; index++) {
            if(!userStorage[_secretId].selectedEnclaves[index].hasAcknowledgedStore)
                continue;
            address enclaveAddress = userStorage[_secretId].selectedEnclaves[index].enclaveAddress;
            uint256 endTimestamp = SECRET_STORE.getSecretStoreLastAliveTimestamp(enclaveAddress);

            uint256 ackTimestamp;
            if(_isReplacedStore(_secretId, index))
                ackTimestamp = userStorage[_secretId].selectedEnclaves[index].replacedAckTimestamp;
            else {
                // if all the stores haven't marked ack
                if(userStorage[_secretId].ackTimestamp == 0)
                    return usdcDeposit;
                else
                    ackTimestamp = userStorage[_secretId].ackTimestamp;
            }

            if(endTimestamp <= ackTimestamp)
                continue;
            uint256 storePayment = (endTimestamp - ackTimestamp) * userStorage[_secretId].sizeLimit * SECRET_STORE_FEE_RATE;
            usdcDeposit -= storePayment;
        }

        return usdcDeposit;
    }

    /**
     * @notice It verifies if msg.sender is either the secret owner or allowed to use a specific secret.
     *         Also checks if the secret has been acknowledged by the original set of selected stores, and can take more jobs.
     *         On successful verification, it returns the list of selected stores that have acknowledged the secret.
     */
    function verifyUserAndGetSelectedStores(
        uint256 _secretId,
        address _jobOwner
    ) external view returns (address[] memory) {
        if(userStorage[_secretId].owner != _jobOwner && !hasSecretAllowedAddress(_secretId, _jobOwner))
            revert SecretManagerUserNotAllowed();

        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        address[] memory selectedStores = new address[](len);
        uint8 env = userStorage[_secretId].env;
        uint256 count;
        for (uint256 index = 0; index < len; index++) {
            address enclaveAddress = userStorage[_secretId].selectedEnclaves[index].enclaveAddress;
            if(userStorage[_secretId].selectedEnclaves[index].hasAcknowledgedStore) {
                if(EXECUTORS.isNodePresentInTree(env, enclaveAddress))
                    selectedStores[count++] = enclaveAddress;
            }
            else if(!_isReplacedStore(_secretId, index))
                revert SecretManagerUnacknowledged();
        }

        if(count != len) {
            // updating the array length directly in memory to return only the ack secret stores that are present in the tree
            assembly {
                mstore(selectedStores, count)
            }
        }

        return selectedStores;
    }

    function hasSecretAllowedAddress(
        uint256 _secretId,
        address _user
    ) public view returns (bool) {
        uint256 len = userStorage[_secretId].allowedAddresses.length;
        for (uint256 index = 0; index < len; index++) {
            if(_user == userStorage[_secretId].allowedAddresses[index])
                return true;
        }
        return false;
    }

    function setSecretAllowedAddresses(
        uint256 _secretId,
        address[] memory _allowedAddresses
    ) external isValidSecretOwner(_secretId) {
        userStorage[_secretId].allowedAddresses = _allowedAddresses;
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- SecretManager functions end --------------------------------//
}
