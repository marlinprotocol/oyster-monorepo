// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IClusterRegistry.sol";
import "./interfaces/IRewardDelegators.sol";


contract ClusterRegistry is
    Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade,
    IClusterRegistry  // interface
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "only admin");
        _;
    }

//-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "Cannot be adminless");
    }

    function _authorizeUpgrade(address /*account*/) onlyAdmin internal view override {}

//-------------------------------- Overrides end --------------------------------//

//-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize(uint256[3] calldata _lockWaitTimes, address _rewardDelegators)
        public
        initializer
    {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        bytes32[3] memory _selectors = [COMMISSION_LOCK_SELECTOR, SWITCH_NETWORK_LOCK_SELECTOR, UNREGISTER_LOCK_SELECTOR];
        for(uint256 i=0; i < _selectors.length; i++) {
            _updateLockWaitTime(_selectors[i], _lockWaitTimes[i]);
        }
        _updateRewardDelegators(_rewardDelegators);
    }

//-------------------------------- Initializer end --------------------------------//

//-------------------------------- Locks start --------------------------------//

    struct Lock {
        uint256 unlockTime;
        uint256 iValue;
    }
    mapping(bytes32 => Lock) public locks;
    mapping(bytes32 => uint256) public lockWaitTime;

    bytes32 constant COMMISSION_LOCK_SELECTOR = keccak256("COMMISSION_LOCK");
    bytes32 constant SWITCH_NETWORK_LOCK_SELECTOR = keccak256("SWITCH_NETWORK_LOCK");
    bytes32 constant UNREGISTER_LOCK_SELECTOR = keccak256("UNREGISTER_LOCK");

    event LockTimeUpdated(bytes32 indexed selector, uint256 prevLockTime, uint256 updatedLockTime);

    function _updateLockWaitTime(bytes32 _selector, uint256 _updatedWaitTime) internal {
        emit LockTimeUpdated(_selector, lockWaitTime[_selector], _updatedWaitTime);
        lockWaitTime[_selector] = _updatedWaitTime;
    }

    function updateLockWaitTime(bytes32 _selector, uint256 _updatedWaitTime) external onlyAdmin {
        _updateLockWaitTime(_selector, _updatedWaitTime);
    }

//-------------------------------- Locks end --------------------------------//

//-------------------------------- Admin calls start --------------------------------//

    function updateRewardDelegators(address _updatedRewardDelegators) external onlyAdmin {
        _updateRewardDelegators(_updatedRewardDelegators);
    }

    function _updateRewardDelegators(address _updatedRewardDelegators) internal {
        rewardDelegators = IRewardDelegators(_updatedRewardDelegators);
        emit RewardDelegatorsUpdated(_updatedRewardDelegators);
    }

//-------------------------------- Admin calls end --------------------------------//

//-------------------------------- Clusters start --------------------------------//

    enum Status{NOT_REGISTERED, REGISTERED}
    struct Cluster {
        bytes32 networkId; // keccak256("ETH") // token ticker for anyother chain in place of ETH
        uint256 commission;
        address rewardAddress;
        address clientKey;
        Status status;
    }
    mapping(address => Cluster) clusters;
    mapping(address => address) public clientKeys;

    IRewardDelegators public rewardDelegators;

    // NEW STORAGE VARS
    bytes32 public constant OPERATOR_REGISTRY_ROLE = keccak256("OPERATOR_REGISTRY_ROLE");

    event ClusterRegistered(
        address indexed cluster,
        bytes32 indexed networkId,
        uint256 commission,
        address rewardAddress,
        address clientKey
    );
    event CommissionUpdateRequested(address indexed cluster, uint256 commissionAfterUpdate, uint256 effectiveTime);
    event CommissionUpdated(address indexed cluster, uint256 updatedCommission, uint256 updatedAt);
    event RewardAddressUpdated(address indexed cluster, address updatedRewardAddress);
    event NetworkSwitchRequested(address indexed cluster, bytes32 indexed networkId, uint256 effectiveTime);
    event NetworkSwitched(address indexed cluster, bytes32 indexed networkId, uint256 updatedAt);
    event ClientKeyUpdated(address indexed cluster, address clientKey);
    event ClusterUnregisterRequested(address indexed cluster, uint256 effectiveTime);
    event ClusterUnregistered(address indexed cluster, uint256 updatedAt);
    event RewardDelegatorsUpdated(address indexed rewardDelegators);

    function registerOperator(
        address _operator,
        bytes memory _data
    ) external onlyRole(OPERATOR_REGISTRY_ROLE) {
        // decode the data to get the details
        (
            bytes32 networkId,
            uint256 commission,
            address rewardAddress,
            address clientKey
        ) = abi.decode(_data, (bytes32, uint256, address, address));

        _register(networkId, commission, rewardAddress, clientKey, _operator);
    }

    function _register(
        bytes32 _networkId,
        uint256 _commission,
        address _rewardAddress,
        address _clientKey,
        address _operator
    ) internal {
        require(
            !isClusterValid(_operator),
            "CR:R-Cluster is already registered"
        );
        require(_commission <= 100, "CR:R-Commission more than 100%");
        require(clientKeys[_clientKey] ==  address(0), "CR:R-Client key is already used");
        clusters[_operator].commission = _commission;
        clusters[_operator].rewardAddress = _rewardAddress;
        clusters[_operator].clientKey = _clientKey;
        clusters[_operator].networkId = _networkId;
        clusters[_operator].status = Status.REGISTERED;

        clientKeys[_clientKey] = _operator;
        rewardDelegators.updateClusterDelegation(_operator, _networkId);

        emit ClusterRegistered(_operator, _networkId, _commission, _rewardAddress, _clientKey);
    }

    function updateCluster(uint256 _commission, bytes32 _networkId, address _rewardAddress, address _clientKey) public {
        if(_networkId != bytes32(0)) {
            requestNetworkSwitch(_networkId);
        }
        if(_rewardAddress != address(0)) {
            updateRewardAddress(_rewardAddress);
        }
        if(_clientKey != address(0)) {
            updateClientKey(_clientKey);
        }
        if(_commission != type(uint256).max) {
            requestCommissionUpdate(_commission);
        }
    }

    function requestCommissionUpdate(uint256 _commission) public {
        require(
            isClusterValid(_msgSender()),
            "CR:RCU-Cluster not registered"
        );
        require(_commission <= 100, "CR:RCU-Commission more than 100%");
        bytes32 lockId = keccak256(abi.encodePacked(COMMISSION_LOCK_SELECTOR, _msgSender()));
        uint256 unlockTime = locks[lockId].unlockTime;
        require(unlockTime == 0, "CR:RCU-Commission update in progress");
        uint256 updatedUnlockBlock = block.timestamp + lockWaitTime[COMMISSION_LOCK_SELECTOR];
        locks[lockId] = Lock(updatedUnlockBlock, _commission);
        emit CommissionUpdateRequested(_msgSender(), _commission, updatedUnlockBlock);
    }

    function updateCommission() public {
        bytes32 lockId = keccak256(abi.encodePacked(COMMISSION_LOCK_SELECTOR, _msgSender()));
        uint256 unlockTime = locks[lockId].unlockTime;
        require(unlockTime != 0, "CR:UCM-No commission update request");
        require(
            unlockTime <= block.timestamp,
            "CR:UCM-Commission update in progress"
        );
        uint256 currentCommission = locks[lockId].iValue;
        clusters[_msgSender()].commission = currentCommission;
        emit CommissionUpdated(_msgSender(), currentCommission, unlockTime);
        delete locks[lockId];
    }

    function requestNetworkSwitch(bytes32 _networkId) public {
        require(
            isClusterValid(_msgSender()),
            "CR:RNS-Cluster not registered"
        );
        bytes32 lockId = keccak256(abi.encodePacked(SWITCH_NETWORK_LOCK_SELECTOR, _msgSender()));
        uint256 unlockTime = locks[lockId].unlockTime;
        require(unlockTime == 0,"CR:RNS-Network switch in progress");
        uint256 updatedUnlockBlock = block.timestamp + lockWaitTime[SWITCH_NETWORK_LOCK_SELECTOR];
        locks[lockId] = Lock(updatedUnlockBlock, uint256(_networkId));
        emit NetworkSwitchRequested(_msgSender(), _networkId, updatedUnlockBlock);
    }

    function switchNetwork() public {
        bytes32 lockId = keccak256(abi.encodePacked(SWITCH_NETWORK_LOCK_SELECTOR, _msgSender()));
        uint256 unlockTime = locks[lockId].unlockTime;
        require(unlockTime != 0, "CR:SN-No switch network request");
        require(
            unlockTime <= block.timestamp,
            "CR:SN-Network switch in progress"
        );
        bytes32 currentNetwork = bytes32(locks[lockId].iValue);
        rewardDelegators.removeClusterDelegation(_msgSender(), clusters[_msgSender()].networkId);
        clusters[_msgSender()].networkId = currentNetwork;
        rewardDelegators.updateClusterDelegation(_msgSender(), currentNetwork);
        emit NetworkSwitched(_msgSender(), currentNetwork, unlockTime);
        delete locks[lockId];
    }

    function updateRewardAddress(address _rewardAddress) public {
        require(
            isClusterValid(_msgSender()),
            "CR:URA-Cluster not registered"
        );
        clusters[_msgSender()].rewardAddress = _rewardAddress;
        emit RewardAddressUpdated(_msgSender(), _rewardAddress);
    }

    function updateClientKey(address _clientKey) public {
        require(
            isClusterValid(_msgSender()),
            "CR:UCK-Cluster not registered"
        );
        require(_clientKey != address(0), "CR:UCK - Client key cannot be zero");
        require(clientKeys[_clientKey] ==  address(0), "CR:UCK - Client key is already used");
        delete clientKeys[clusters[_msgSender()].clientKey];
        clusters[_msgSender()].clientKey = _clientKey;
        clientKeys[_clientKey] = _msgSender();
        emit ClientKeyUpdated(_msgSender(), _clientKey);
    }

    function requestUnregister(address _operator) external onlyRole(OPERATOR_REGISTRY_ROLE) {
        require(
            isClusterValid(_operator),
            "CR:RU-Cluster not registered"
        );
        bytes32 lockId = keccak256(abi.encodePacked(UNREGISTER_LOCK_SELECTOR, _operator));
        uint256 unlockTime = locks[lockId].unlockTime;
        require(unlockTime == 0, "CR:RU-Unregistration already in progress");
        uint256 updatedUnlockBlock = block.timestamp + lockWaitTime[UNREGISTER_LOCK_SELECTOR];
        locks[lockId] = Lock(updatedUnlockBlock, 0);
        emit ClusterUnregisterRequested(_operator, updatedUnlockBlock);
    }

    function unregister(address _operator) external onlyRole(OPERATOR_REGISTRY_ROLE) {
        require(
            clusters[_operator].status != Status.NOT_REGISTERED,
            "CR:UR-Cluster not registered"
        );
        bytes32 lockId = keccak256(abi.encodePacked(UNREGISTER_LOCK_SELECTOR, _operator));
        uint256 unlockTime = locks[lockId].unlockTime;
        require(unlockTime != 0, "CR:UR-No unregistration request");
        require(
            unlockTime <= block.timestamp,
            "CR:UR-Unregistration already in progress"
        );
        clusters[_operator].status = Status.NOT_REGISTERED;
        emit ClusterUnregistered(_operator, unlockTime);
        delete clientKeys[clusters[_operator].clientKey];
        delete locks[lockId];
        delete locks[keccak256(abi.encodePacked(COMMISSION_LOCK_SELECTOR, _operator))];
        delete locks[keccak256(abi.encodePacked(SWITCH_NETWORK_LOCK_SELECTOR, _operator))];
        rewardDelegators.removeClusterDelegation(_operator, clusters[_operator].networkId);
    }

    function getCommission(address _cluster) public view returns(uint256) {
        return clusters[_cluster].commission;
    }

    function getNetwork(address _cluster) public view returns(bytes32) {
        return clusters[_cluster].networkId;
    }

    function getRewardAddress(address _cluster) public view returns(address) {
        return clusters[_cluster].rewardAddress;
    }

    function getClientKey(address _cluster) public view returns(address) {
        return clusters[_cluster].clientKey;
    }

    function getCluster(address _cluster) external view returns(
        uint256 commission,
        address rewardAddress,
        address clientKey,
        bytes32 networkId,
        bool isValidCluster
    ) {
        return (
            getCommission(_cluster),
            getRewardAddress(_cluster),
            getClientKey(_cluster),
            getNetwork(_cluster),
            isClusterValid(_cluster)
        );
    }

    function getRewardInfo(address _cluster) external view returns(uint256, address) {
        return (getCommission(_cluster), getRewardAddress(_cluster));
    }

    function isClusterValid(address _cluster) public view returns(bool) {
        return (clusters[_cluster].status != Status.NOT_REGISTERED);    // returns true if the status is registered
    }

//-------------------------------- Clusters end --------------------------------//
}
