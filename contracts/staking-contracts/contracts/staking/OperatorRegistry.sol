// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IOperatorRegistry.sol";
import "./interfaces/IClusterRegistry.sol";
import "./interfaces/IOperatorManager.sol";
import "./interfaces/IRewardDelegators.sol";

contract OperatorRegistry is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    ERC1967UpgradeUpgradeable, // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable, // public upgrade,
    IOperatorRegistry // interface
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

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "Cannot be adminless");
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyAdmin {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize(address _rewardDelegators) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _updateRewardDelegators(_rewardDelegators);
    }

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Admin calls start --------------------------------//

    function updateRewardDelegators(address _updatedRewardDelegators) external onlyAdmin {
        _updateRewardDelegators(_updatedRewardDelegators);
    }

    function _updateRewardDelegators(address _updatedRewardDelegators) internal {
        rewardDelegators = IRewardDelegators(_updatedRewardDelegators);
        emit RewardDelegatorsUpdated(_updatedRewardDelegators);
    }

    //-------------------------------- Admin calls end --------------------------------//

    struct OperatorManagerInfo {
        address operatorManager; // ClusterRegistry, Executors
        address operatorRewards; // ClusterRewards, Executors
        address operatorSelector; // Executors
        address rewardToken;    // POND for cluster, USDC for executors
        bool isTwoStepDeregister;
    }

    // operatorManagerId => OperatorManagerInfo
    mapping(bytes32 => OperatorManagerInfo) public operatorManagers;
    // operator => operatorManagerId
    mapping(address => bytes32) public operatorToManagerId;

    // operator manager IDs -
    // Relay service - keccak256("RELAY")
    // Serverless executor service - keccak256("SERVERLESS_EXECUTOR")
    // Serverless gateway service - keccak256("SERVERLESS_GATEWAY")

    IRewardDelegators public rewardDelegators;

    IClusterRegistry public clusterRegistry;

    event RewardDelegatorsUpdated(address indexed rewardDelegators);
    event ServiceAdded(bytes32 indexed operatorManagerId, address operatorManager, bool isTwoStepDeregister);
    event OperatorRegistered(address indexed operator, bytes32 indexed operatorManagerId);
    event DeregisterRequested(address indexed operator, bytes32 indexed operatorManagerId);
    event OperatorDeregistered(address indexed operator, bytes32 indexed operatorManagerId);

    error OperatorRegistry_ServiceAlreadyExists();
    error OperatorRegistry_ServiceNotFound();
    error OperatorRegistry_OperatorAlreadyRegistered();
    error OperatorRegistry_OperatorNotRegistered();
    error OperatorRegistry_TwoStepDeregisterDisabled();
    error OperatorRegistry_DeregisterRequestFailed();
    error OperatorRegistry_DeregistrationFailed();

    function addService(
        bytes32 _operatorManagerId,
        address _operatorManager,
        address _operatorRewards,
        address _operatorSelector,
        address _rewardToken,
        bool _isTwoStepDeregister
    ) external onlyAdmin {
        if(operatorManagers[_operatorManagerId].operatorManager != address(0))
            revert OperatorRegistry_ServiceAlreadyExists();

        operatorManagers[_operatorManagerId] = OperatorManagerInfo({
            operatorManager: _operatorManager,
            operatorRewards: _operatorRewards,
            operatorSelector: _operatorSelector,
            rewardToken: _rewardToken,
            isTwoStepDeregister: _isTwoStepDeregister
        });

        emit ServiceAdded(_operatorManagerId, _operatorManager, _isTwoStepDeregister);
    }

    // TODO: Instead of passing the _operator, we can use the msg.sender
    function register(address _operator, bytes32 _operatorManagerId, bytes calldata _data) external {
        if(operatorManagers[_operatorManagerId].operatorManager == address(0))
            revert OperatorRegistry_ServiceNotFound();
        if(operatorToManagerId[_operator] != 0 || clusterRegistry.isClusterValid(_operator))
            revert OperatorRegistry_OperatorAlreadyRegistered();

        // call to the operator manager to register the operator
        address operatorManager = operatorManagers[_operatorManagerId].operatorManager;
        IOperatorManager(operatorManager).registerOperator(_operator, _data);

        operatorToManagerId[_operator] = _operatorManagerId;

        emit OperatorRegistered(_operator, _operatorManagerId);
    }

    function requestDeregister(bytes calldata _data) external {
        address operator = _msgSender();
        bytes32 id = operatorToManagerId[operator];
        if(id == bytes32(0))
            revert OperatorRegistry_OperatorNotRegistered();

        if(!operatorManagers[id].isTwoStepDeregister)
            revert OperatorRegistry_TwoStepDeregisterDisabled();

        // Low-level call to the operator manager to request deregistration
        // if case for Relay service, else case for serverless service
        bool success;
        if(_data.length == 0) {
            (success, ) = operatorManagers[id].operatorManager.call(
                abi.encodeWithSignature("requestDeregister(address)", operator)
            );
        } else {
            (success, ) = operatorManagers[id].operatorManager.call(
                abi.encodeWithSignature("requestDeregister(address,bytes)", operator, _data)
            );
        }

        if(!success)
            revert OperatorRegistry_DeregisterRequestFailed();
        
        emit DeregisterRequested(operator, id);
    }

    function deregister(bytes calldata _data) external {
        address operator = _msgSender();
        bytes32 id = operatorToManagerId[operator];
        if(id == bytes32(0))
            revert OperatorRegistry_OperatorNotRegistered();

        if(!operatorManagers[id].isTwoStepDeregister)
            revert OperatorRegistry_TwoStepDeregisterDisabled();

        // Low-level call to the operator manager to request deregistration
        // if case for Relay service, else case for serverless service
        bool success;
        if(_data.length == 0) {
            (success, ) = operatorManagers[id].operatorManager.call(
                abi.encodeWithSignature("unregister(address)", operator)
            );
        } else {
            (success, ) = operatorManagers[id].operatorManager.call(
                abi.encodeWithSignature("deregisterOperator(address,bytes)", operator, _data)
            );
        }

        if(!success)
            revert OperatorRegistry_DeregistrationFailed();

        delete operatorToManagerId[operator];
        emit OperatorDeregistered(operator, id);
    }

    function getOperatorManager(bytes32 _operatorManagerId) external view returns (address) {
        return operatorManagers[_operatorManagerId].operatorManager;
    }

    function getOperatorRewards(bytes32 _operatorManagerId) external view returns (address) {
        return operatorManagers[_operatorManagerId].operatorRewards;
    }

    function getOperatorSelector(bytes32 _operatorManagerId) external view returns (address) {
        return operatorManagers[_operatorManagerId].operatorSelector;
    }

    function getRewardToken(bytes32 _operatorManagerId) external view returns (address) {
        return operatorManagers[_operatorManagerId].rewardToken;
    }
}
