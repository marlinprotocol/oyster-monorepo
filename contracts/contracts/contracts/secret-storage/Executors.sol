// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../serverless-v2/tree/TreeMapUpgradeable.sol";
import "./TeeManager.sol";

/**
 * @title Executors Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract Executors is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    TreeMapUpgradeable
{
    /// @notice Thrown when the provided TeeManager address is zero.
    error ExecutorsZeroAddressTeeManager();

    /**
     * @dev Initializes the logic contract without any admins, safeguarding against takeover.
     * @param _teeManager The TeeManager contract.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        TeeManager _teeManager
    ) {
        _disableInitializers();

        if (address(_teeManager) == address(0)) revert ExecutorsZeroAddressTeeManager();

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
    error ExecutorsZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin.
     * @param _admin The address of the admin.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert ExecutorsZeroAddressAdmin();

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

    uint256 public constant INIT_REPUTATION = 1000;

    uint256 public MIN_STAKE_AMOUNT;

    //-------------------------------- Executors start --------------------------------//

    modifier onlyTeeManager() {
        _onlyTeeManager();
        _;
    }

    function _onlyTeeManager() internal view {
        if (_msgSender() != address(TEE_MANAGER))
            revert ExecutorsNotTeeManager();
    }

    struct Executor {
        uint256 jobCapacity;
        uint256 activeJobs;
        uint256 reputation;
    }

    // enclaveAddress => executor node details
    mapping(address => Executor) public executors;

    error ExecutorsGlobalEnvAlreadySupported();
    error ExecutorsGlobalEnvAlreadyUnsupported();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that has pending jobs.
    error ExecutorsHasPendingJobs();
    /// @notice Thrown when the provided enclave owner does not match the stored owner.
    error ExecutorsNotTeeManager();
    /// @notice Thrown when the provided execution environment is not supported globally.
    error ExecutorsUnsupportedEnv();
    error ExecutorsUnavailableStores();

    modifier isValidEnv(uint8 _env) {
        _isValidEnv(_env);
        _;
    }

    function _isValidEnv(uint8 _env) internal view {
        if (!isTreeInitialized(_env)) 
            revert ExecutorsUnsupportedEnv();
    }

    //----------------------------- TeeManagerRole functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _registerExecutor(
        address _enclaveAddress,
        uint256 _jobCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) internal {
        executors[_enclaveAddress].jobCapacity = _jobCapacity;
        executors[_enclaveAddress].reputation = INIT_REPUTATION;

        if (_stakeAmount >= MIN_STAKE_AMOUNT)
            _insert_unchecked(_env, _enclaveAddress, uint64(_stakeAmount / STAKE_ADJUSTMENT_FACTOR));
    }

    function _drainExecutor(
        address _enclaveAddress,
        uint8 _env
    ) internal {
        // remove node from the tree
        _deleteIfPresent(_env, _enclaveAddress);
    }

    function _reviveExecutor(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stakeAmount
    ) internal {
        // insert node in the tree
        if (executors[_enclaveAddress].activeJobs < executors[_enclaveAddress].jobCapacity) {
            _insert_unchecked(_env, _enclaveAddress, uint64(_stakeAmount / STAKE_ADJUSTMENT_FACTOR));
        }
    }

    function _deregisterExecutor(address _enclaveAddress) internal {
        if (executors[_enclaveAddress].activeJobs != 0) 
            revert ExecutorsHasPendingJobs();

        delete executors[_enclaveAddress];
    }

    function _upsertTreeNode(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stake
    ) internal {
        if (executors[_enclaveAddress].activeJobs < executors[_enclaveAddress].jobCapacity) {
            _upsert(_env, _enclaveAddress, uint64(_stake / STAKE_ADJUSTMENT_FACTOR));
        }
    }

    function _removeExecutorStake(address _enclaveAddress) internal view {
        if (executors[_enclaveAddress].activeJobs != 0)
            revert ExecutorsHasPendingJobs();
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function registerExecutor(
        address _enclaveAddress,
        uint256 _jobCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) external isValidEnv(_env) onlyTeeManager {
        _registerExecutor(
            _enclaveAddress,
            _jobCapacity,
            _env,
            _stakeAmount
        );
    }

    /**
     * @notice Deregisters an enclave node.
     * @param _enclaveAddress The address of the enclave to deregister.
     * @dev Caller must be the owner of the enclave node.
     */
    function deregisterExecutor(address _enclaveAddress) external onlyTeeManager {
        _deregisterExecutor(_enclaveAddress);
    }

    /**
     * @notice Drains an enclave node, making it inactive for new secret stores.
     * @param _enclaveAddress The address of the enclave to drain.
     * @dev Caller must be the owner of the enclave node.
     */
    function drainExecutor(
        address _enclaveAddress,
        uint8 _env
    ) external onlyTeeManager {
        _drainExecutor(_enclaveAddress, _env);
    }

    /**
     * @notice Revives a previously drained enclave node.
     * @param _enclaveAddress The address of the enclave to revive.
     * @dev Caller must be the owner of the enclave node.
     */
    function reviveExecutor(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stakeAmount
    ) external onlyTeeManager {
        _reviveExecutor(_enclaveAddress, _env, _stakeAmount);
    }

    /**
     * @notice Adds stake to an enclave node.
     * @param _enclaveAddress The address of the enclave to add stake to.
     * @param _stake The amount of stake.
     * @dev Caller must be the owner of the enclave node.
     */
    function addExecutorStake(
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
    function removeExecutorStake(
        address _enclaveAddress
    ) external view onlyTeeManager {
        _removeExecutorStake(_enclaveAddress);
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

    //------------------------------ TeeManagerRole functions end --------------------------------//

    //-------------------------------- JobsRole functions start ---------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _selectExecutionNodes(
        uint8 _env,
        address[] memory selectedStores,
        uint256 _noOfNodesToSelect
    ) internal returns (address[] memory) {
        // sort the stakeAmounts list, and get the top N elements
        address[] memory topNStores;
        if(selectedStores.length > 0) {
            topNStores = _getTopNStores(selectedStores, _noOfNodesToSelect);
            _updateExecutorsResource(_env, topNStores);
        }
        uint256 storesCount = topNStores.length;

        uint256 noOfExecutorsToSelect = _noOfNodesToSelect > storesCount ? _noOfNodesToSelect - storesCount : 0;
        // TODO: not selecting from the executors until selection algo issue is fixed
        if(noOfExecutorsToSelect > 0)
            revert ExecutorsUnavailableStores();

        return topNStores;
    }

    // function _selectExecutors(
    //     uint8 _env,
    //     uint256 _noOfNodesToSelect
    // ) internal returns (address[] memory selectedNodes) {
    //     selectedNodes = _selectNodes(_env, _noOfNodesToSelect);
    //     _updateExecutorsResource(_env, selectedNodes);
    // }

    // function _selectNodes(
    //     uint8 _env,
    //     uint256 _noOfNodesToSelect
    // ) internal view returns (address[] memory selectedNodes) {
    //     uint256 randomizer = uint256(keccak256(abi.encode(blockhash(block.number - 1), block.timestamp)));
    //     selectedNodes = _selectN(_env, randomizer, _noOfNodesToSelect);
    // }

    function _getTopNStores(
        address[] memory selectedStores,
        uint256 noOfStoresToSelect
    ) internal view returns (address[] memory topNStores) {
        uint256[] memory storesStakes = TEE_MANAGER.getTeeNodesStake(selectedStores);
        // Sorting the array in descending order using bubble sort
        uint256 len = selectedStores.length;
        for (uint256 i = 0; i < len; i++) {
            for (uint256 j = 0; j < len - i - 1; j++) {
                if (storesStakes[j] < storesStakes[j + 1]) {
                    // Swap elements
                    address temp1 = selectedStores[j];
                    selectedStores[j] = selectedStores[j + 1];
                    selectedStores[j + 1] = temp1;

                    uint256 temp2 = storesStakes[j];
                    storesStakes[j] = storesStakes[j + 1];
                    storesStakes[j + 1] = temp2;
                }
            }
        }

        if(len > noOfStoresToSelect)
            len = noOfStoresToSelect;

        // Create a new array to hold the top N values
        topNStores = new address[](len);
        for (uint256 i = 0; i < len; i++)
            topNStores[i] = selectedStores[i];
    }

    // function _deleteTreeNodes(
    //     uint8 _env,
    //     address[] memory _enclaveAddresses
    // ) internal {
    //     uint256 len = _enclaveAddresses.length;
    //     for (uint256 index = 0; index < len; index++) {
    //         _deleteIfPresent(_env, _enclaveAddresses[index]);
    //     }
    // }

    // function _addTreeNodes(
    //     uint8 _env,
    //     address[] memory _enclaveAddresses
    // ) internal {
    //     uint256[] memory stakeAmounts = TEE_MANAGER.getTeeNodesStake(_enclaveAddresses);
    //     uint256 len = _enclaveAddresses.length;
    //     for (uint256 index = 0; index < len; index++) {
    //         address enclaveAddress = _enclaveAddresses[index];
    //         if (executors[enclaveAddress].activeJobs < executors[enclaveAddress].jobCapacity)
    //             _insert_unchecked(_env, enclaveAddress, uint64(stakeAmounts[index] / STAKE_ADJUSTMENT_FACTOR));
    //     }
    // }

    function _updateExecutorsResource(
        uint8 _env,
        address[] memory _selectedNodes
    ) internal {
        for (uint256 index = 0; index < _selectedNodes.length; index++) {
            address enclaveAddress = _selectedNodes[index];
            executors[enclaveAddress].activeJobs += 1;

            // if jobCapacity reached then delete from the tree so as to not consider this node in new jobs allocation
            if (executors[enclaveAddress].activeJobs == executors[enclaveAddress].jobCapacity)
                _deleteIfPresent(_env, enclaveAddress);
        }
    }

    function _releaseExecutor(
        address _enclaveAddress
    ) internal {
        executors[_enclaveAddress].activeJobs -= 1;
        TEE_MANAGER.updateTreeState(_enclaveAddress);
    }

    function _slashExecutor(address _enclaveAddress, address _recipient) internal returns (uint256) {    
        uint256 slashedAmount = TEE_MANAGER.slashExecutor(_enclaveAddress, _recipient);

        _releaseExecutor(_enclaveAddress);

        // TODO: decrease reputation logic
        executors[_enclaveAddress].reputation -= 10;
        return slashedAmount;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function initTree(uint8 _env) external onlyRole(JOBS_ROLE) {
        if (isTreeInitialized(_env)) 
            revert ExecutorsGlobalEnvAlreadySupported();

        _init_tree(_env);
    }

    function removeTree(uint8 _env) external onlyRole(JOBS_ROLE) {
        if (!isTreeInitialized(_env)) 
            revert ExecutorsGlobalEnvAlreadyUnsupported();

        _delete_tree(_env);
    }

    /**
     * @notice Selects a number of executor nodes for job assignments.
     * @dev Executors are selected randomly based on the stake distribution.
     * @param _env The execution environment supported by the enclave.
     * @param _noOfNodesToSelect The number of nodes to select.
     * @return selectedNodes An array of selected node addresses.
     */
    function selectExecutionNodes(
        uint8 _env,
        address[] memory selectedStores,
        uint256 _noOfNodesToSelect
    ) external onlyRole(JOBS_ROLE) isValidEnv(_env) returns (address[] memory) {
        return _selectExecutionNodes(_env, selectedStores, _noOfNodesToSelect);
    }

    /**
     * @notice Releases an executor node on job response submission, thus reducing its active jobs.
     * @dev Can only be called by an account with the `JOBS_ROLE`.
     * @param _enclaveAddress The address of the executor enclave to release.
     */
    function releaseExecutor(
        address _enclaveAddress
    ) external onlyRole(JOBS_ROLE) {
        _releaseExecutor(_enclaveAddress);
    }

    /**
     * @notice Slashes the stake of an executor node.
     * @dev Can only be called by an account with the `JOBS_ROLE`. This function
     *      triggers a slashing penalty on the specified executor node.
     * @param _enclaveAddress The address of the executor enclave to be slashed.
     * @return The amount of stake that was slashed from the executor node.
     */
    function slashExecutor(address _enclaveAddress) external onlyRole(JOBS_ROLE) returns (uint256) {
        return _slashExecutor(_enclaveAddress, _msgSender());
    }

    function increaseReputation(address _enclaveAddress, uint256 _value) external onlyRole(JOBS_ROLE) {
        executors[_enclaveAddress].reputation += _value;
    }

    function decreaseReputation(address _enclaveAddress, uint256 _value) external onlyRole(JOBS_ROLE) {
        executors[_enclaveAddress].reputation -= _value;
    }

    //---------------------------------- external functions end ------------------------------------//

    //---------------------------------- JobsRole functions end -------------------------------------//

}
