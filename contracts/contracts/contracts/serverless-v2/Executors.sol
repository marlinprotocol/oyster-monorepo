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
import "../AttestationAutherUpgradeable.sol";
import "./tree/TreeMapUpgradeable.sol";
import "../interfaces/IAttestationVerifier.sol";
import "../staking/interfaces/IRewardDelegators.sol";

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
    AttestationAutherUpgradeable,
    TreeMapUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Thrown when the provided ERC20 token address is zero.
    error ExecutorsZeroAddressToken();
    /// @notice Thrown when the provided minimum stake amount is zero.
    error ExecutorsZeroMinStakeAmount();

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
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        uint256 _minStakeAmount,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if (address(_token) == address(0)) revert ExecutorsZeroAddressToken();
        if (_minStakeAmount == 0) revert ExecutorsZeroMinStakeAmount();

        TOKEN = _token;
        MIN_STAKE_AMOUNT = _minStakeAmount;

        SLASH_PERCENT_IN_BIPS = _slashPercentInBips;
        SLASH_MAX_BIPS = _slashMaxBips;
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
     * @dev Initializes the contract with the given admin and enclave images.
     * @param _admin The address of the admin.
     * @param _images Array of enclave images to initialize.
     */
    function initialize(address _admin, EnclaveImage[] memory _images) public initializer {
        if (_admin == address(0)) revert ExecutorsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);
        __TreeMapUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MIN_STAKE_AMOUNT;

    /// @notice an integer in the range 0-10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_PERCENT_IN_BIPS;

    /// @notice expected to be 10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_MAX_BIPS;

    /// @notice executor stake amount will be divided by 10^18 before adding to the tree
    uint256 public constant STAKE_ADJUSTMENT_FACTOR = 1e18;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");
    bytes32 public constant OPERATOR_REGISTRY_ROLE = keccak256("OPERATOR_REGISTRY_ROLE");

    IRewardDelegators public immutable REWARD_DELEGATORS;

    //-------------------------------- Execution Env start --------------------------------//

    modifier isValidEnv(uint8 _env) {
        if (!isTreeInitialized(_env)) revert ExecutorsUnsupportedEnv();
        _;
    }

    function initTree(uint8 _env) external onlyRole(JOBS_ROLE) {
        _init_tree(_env);
    }

    function removeTree(uint8 _env) external onlyRole(JOBS_ROLE) {
        _delete_tree(_env);
    }

    //-------------------------------- Execution Env end --------------------------------//

    //-------------------------------- Executor start --------------------------------//

    modifier isValidExecutorOwner(address _enclaveAddress, address _owner) {
        _isValidExecutorOwner(_enclaveAddress, _owner);
        _;
    }

    function _isValidExecutorOwner(address _enclaveAddress, address _owner) internal view {
        if (executors[_enclaveAddress].owner != _owner) 
            revert ExecutorsInvalidOwner();
    }

    modifier isRewardDelegators() {
        if(_msgSender() != address(REWARD_DELEGATORS))
            revert ExecutorsInvalidRewardDelegators();
        _;
    }

    struct Executor {
        uint256 jobCapacity;
        uint256 activeJobs;
        // uint256 stakeAmount;
        uint256 rewardAmount;
        uint256 commission;
        address owner;
        bool draining;
        uint8 env;
    }

    // enclaveAddress => Execution node details
    mapping(address => Executor) public executors;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Executors"),
                keccak256("1")
            )
        );

    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(address owner,uint256 jobCapacity,uint8 env,uint256 signTimestamp)");

    /// @notice Emitted when a new executor is registered.
    /// @param enclaveAddress The address of the enclave.
    /// @param owner The owner of the executor.
    /// @param env The execution environment supported by the enclave.
    /// @param jobCapacity The maximum number of jobs the executor can handle in parallel.
    event ExecutorRegistered(
        address indexed enclaveAddress,
        address indexed owner,
        uint256 jobCapacity,
        uint8 env,
        uint256 commission
    );

    /// @notice Emitted when an executor is deregistered.
    /// @param enclaveAddress The address of the enclave.
    event ExecutorDeregistered(address indexed enclaveAddress);

    /// @notice Emitted when an executor is drained.
    /// @param enclaveAddress The address of the enclave.
    event ExecutorDrained(address indexed enclaveAddress);

    /// @notice Emitted when an executor is revived.
    /// @param enclaveAddress The address of the enclave.
    event ExecutorRevived(address indexed enclaveAddress);

    /// @notice Emitted when stake is added to an executor.
    /// @param enclaveAddress The address of the enclave.
    /// @param addedAmount The amount of stake added.
    event ExecutorStakeAdded(address indexed enclaveAddress, uint256 addedAmount);

    /// @notice Emitted when stake is removed from an executor.
    /// @param enclaveAddress The address of the enclave.
    /// @param removedAmount The amount of stake removed.
    event ExecutorStakeRemoved(address indexed enclaveAddress, uint256 removedAmount);

    error ExecutorsInvalidRewardDelegators();
    /// @notice Thrown when the signature timestamp has expired.
    error ExecutorsSignatureTooOld();
    /// @notice Thrown when the signer of the registration data is invalid.
    error ExecutorsInvalidSigner();
    /// @notice Thrown when attempting to register an executor that already exists.
    error ExecutorsExecutorAlreadyExists();
    /// @notice Thrown when attempting to drain an executor that is already draining.
    error ExecutorsAlreadyDraining();
    /// @notice Thrown when attempting to revive an executor that is not draining.
    error ExecutorsAlreadyRevived();
    /// @notice Thrown when attempting to deregister or remove stake from an executor that is not draining.
    error ExecutorsNotDraining();
    /// @notice Thrown when attempting to deregister or remove stake from an executor that has pending jobs.
    error ExecutorsHasPendingJobs();
    /// @notice Thrown when the provided executor owner does not match the stored owner.
    error ExecutorsInvalidOwner();
    /// @notice Thrown when the provided execution environment is not supported globally.
    error ExecutorsUnsupportedEnv();

    //-------------------------------- Admin methods start --------------------------------//

    /**
     * @notice Whitelists an enclave image for use by executors.
     * @param PCR0 The first PCR value.
     * @param PCR1 The second PCR value.
     * @param PCR2 The third PCR value.
     * @return imageId The ID of the whitelisted image.
     * @return success Boolean indicating whether the image was successfully whitelisted.
     */
    function whitelistEnclaveImage(
        bytes memory PCR0,
        bytes memory PCR1,
        bytes memory PCR2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32, bool) {
        return _whitelistEnclaveImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    /**
     * @notice Revokes a previously whitelisted enclave image.
     * @param imageId The ID of the image to revoke.
     * @return success Boolean indicating whether the image was successfully revoked.
     */
    function revokeEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(imageId);
    }

    //-------------------------------- Admin methods end ----------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _registerExecutor(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _commission,
        uint8 _env,
        address _owner
    ) internal {
        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        if (executors[enclaveAddress].owner != address(0)) revert ExecutorsExecutorAlreadyExists();

        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        // signature check
        _verifySign(enclaveAddress, _owner, _jobCapacity, _env, _commission, _signTimestamp, _signature);

        _register(enclaveAddress, _owner, _jobCapacity, _env, _commission);

        REWARD_DELEGATORS.updateOperatorDelegation(enclaveAddress, bytes(""));

        // // add node to the tree if min stake amount deposited
        // if (_stakeAmount >= MIN_STAKE_AMOUNT)
        //     _insert_unchecked(_env, enclaveAddress, uint64(_stakeAmount / STAKE_ADJUSTMENT_FACTOR));

        // _addStake(enclaveAddress, _stakeAmount);
    }

    function _verifySign(
        address _enclaveAddress,
        address _owner,
        uint256 _jobCapacity,
        uint8 _env,
        uint256 _commission,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE) revert ExecutorsSignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(REGISTER_TYPEHASH, _owner, _jobCapacity, _env, _commission, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert ExecutorsInvalidSigner();
    }

    function _register(address _enclaveAddress, address _owner, uint256 _jobCapacity, uint8 _env, uint256 _commission) internal {
        executors[_enclaveAddress].jobCapacity = _jobCapacity;
        executors[_enclaveAddress].owner = _owner;
        executors[_enclaveAddress].env = _env;
        executors[_enclaveAddress].commission = _commission;

        emit ExecutorRegistered(_enclaveAddress, _owner, _jobCapacity, _env, _commission);
    }

    function _drainExecutor(address _enclaveAddress) internal {
        if (executors[_enclaveAddress].draining) revert ExecutorsAlreadyDraining();

        executors[_enclaveAddress].draining = true;

        // remove node from the tree
        _deleteIfPresent(executors[_enclaveAddress].env, _enclaveAddress);

        emit ExecutorDrained(_enclaveAddress);
    }

    function _reviveExecutor(address _enclaveAddress) internal {
        Executor memory executorNode = executors[_enclaveAddress];
        if (!executorNode.draining) revert ExecutorsAlreadyRevived();

        executors[_enclaveAddress].draining = false;

        uint256 totalDelegation = REWARD_DELEGATORS.getEffectiveDelegation(_enclaveAddress, keccak256("SERVERLESS_EXECUTOR"));
        // insert node in the tree
        if (totalDelegation >= MIN_STAKE_AMOUNT && executorNode.activeJobs < executorNode.jobCapacity) {
            _insert_unchecked(
                executorNode.env,
                _enclaveAddress,
                uint64(totalDelegation / STAKE_ADJUSTMENT_FACTOR)
            );
        }

        emit ExecutorRevived(_enclaveAddress);
    }

    function _deregisterExecutor(address _enclaveAddress) internal {
        if (!executors[_enclaveAddress].draining) revert ExecutorsNotDraining();
        if (executors[_enclaveAddress].activeJobs != 0) revert ExecutorsHasPendingJobs();

        // _removeStake(_enclaveAddress, executors[_enclaveAddress].stakeAmount);
        REWARD_DELEGATORS.removeOperatorDelegation(_enclaveAddress, bytes(""));

        // TODO: do we need to delete or mark as deregistered?
        _revokeEnclaveKey(_enclaveAddress);
        // delete executors[_enclaveAddress];

        emit ExecutorDeregistered(_enclaveAddress);
    }

    // to be called during (1) operator registration (2) stake updates (delegation, undelegation, withdraw rewards)
    function updateOperatorSelector(address _enclaveAddress, uint256 _totalDelegation) external {
        Executor memory executorNode = executors[_enclaveAddress];

        if (
            !executorNode.draining &&
            executorNode.activeJobs < executorNode.jobCapacity &&
            _totalDelegation >= MIN_STAKE_AMOUNT
        ) {
            // if prevStake is less than min stake, then insert node in tree, else update the node value in tree
            _upsert(executorNode.env, _enclaveAddress, uint64(_totalDelegation / STAKE_ADJUSTMENT_FACTOR));
        } else {
            _deleteIfPresent(executorNode.env, _enclaveAddress);
        }
    }

    function removeOperatorSelector(address _enclaveAddress) external {
        if (!executors[_enclaveAddress].draining) revert ExecutorsNotDraining();
        if (executors[_enclaveAddress].activeJobs != 0) revert ExecutorsHasPendingJobs();
    }

    // function _addExecutorStake(uint256 _amount, address _enclaveAddress) internal {
    //     Executor memory executorNode = executors[_enclaveAddress];
    //     uint256 updatedStake = executorNode.stakeAmount + _amount;

    //     if (
    //         !executorNode.draining &&
    //         executorNode.activeJobs < executorNode.jobCapacity &&
    //         updatedStake >= MIN_STAKE_AMOUNT
    //     ) {
    //         // if prevStake is less than min stake, then insert node in tree, else update the node value in tree
    //         _upsert(executorNode.env, _enclaveAddress, uint64(updatedStake / STAKE_ADJUSTMENT_FACTOR));
    //     }

    //     _addStake(_enclaveAddress, _amount);
    // }

    // function _removeExecutorStake(uint256 _amount, address _enclaveAddress) internal {
    //     if (!executors[_enclaveAddress].draining) revert ExecutorsNotDraining();
    //     if (executors[_enclaveAddress].activeJobs != 0) revert ExecutorsHasPendingJobs();

    //     _removeStake(_enclaveAddress, _amount);
    // }

    // function _addStake(address _enclaveAddress, uint256 _amount) internal {
    //     executors[_enclaveAddress].stakeAmount += _amount;
    //     // transfer stake
    //     TOKEN.safeTransferFrom(executors[_enclaveAddress].owner, address(this), _amount);

    //     emit ExecutorStakeAdded(_enclaveAddress, _amount);
    // }

    // function _removeStake(address _enclaveAddress, uint256 _amount) internal {
    //     executors[_enclaveAddress].stakeAmount -= _amount;
    //     // transfer stake
    //     TOKEN.safeTransfer(executors[_enclaveAddress].owner, _amount);

    //     emit ExecutorStakeRemoved(_enclaveAddress, _amount);
    // }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    // /**
    //  * @notice Registers a new executor node.
    //  * @param _attestationSignature The attestation signature for verification.
    //  * @param _attestation The attestation details.
    //  * @param _jobCapacity The maximum number of jobs the executor can handle in parallel.
    //  * @param _signTimestamp The timestamp when the signature was created.
    //  * @param _signature The signature to verify the registration.
    //  * @param _stakeAmount The amount of stake to be deposited.
    //  * @param _env The execution environment supported by the enclave.
    //  */
    // function registerExecutor(
    //     bytes memory _attestationSignature,
    //     IAttestationVerifier.Attestation memory _attestation,
    //     uint256 _jobCapacity,
    //     uint256 _signTimestamp,
    //     bytes memory _signature,
    //     uint256 _stakeAmount,
    //     uint8 _env
    // ) external isValidEnv(_env) {
    //     _registerExecutor(
    //         _attestationSignature,
    //         _attestation,
    //         _jobCapacity,
    //         _signTimestamp,
    //         _signature,
    //         _stakeAmount,
    //         _env,
    //         _msgSender()
    //     );
    // }

    function registerOperator(
        address _operator,
        bytes calldata _data
    ) external onlyRole(OPERATOR_REGISTRY_ROLE) {
        // decode the data to get the details
        (
            bytes memory attestationSignature,
            IAttestationVerifier.Attestation memory attestation,
            uint256 jobCapacity,
            uint256 signTimestamp,
            bytes memory signature,
            uint256 stakeAmount,
            uint8 env
        ) = abi.decode(_data, (bytes, IAttestationVerifier.Attestation, uint256, uint256, bytes, uint256, uint8));

        _registerExecutor(
            attestationSignature,
            attestation,
            jobCapacity,
            signTimestamp,
            signature,
            stakeAmount,
            env,
            _operator
        );

    }

    // /**
    //  * @notice Deregisters an executor node.
    //  * @param _enclaveAddress The address of the executor enclave to deregister.
    //  * @dev Caller must be the owner of the executor node.
    //  */
    // function deregisterExecutor(address _enclaveAddress) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
    //     _deregisterExecutor(_enclaveAddress);
    // }

    function deregisterOperator(address _operator, bytes memory _data) external onlyRole(OPERATOR_REGISTRY_ROLE) {
        // decode the data to get the enclave address
        address enclaveAddress = abi.decode(_data, (address));
        _isValidExecutorOwner(enclaveAddress, _operator);

        _deregisterExecutor(enclaveAddress);
    }

    /**
     * @notice Drains an executor node, making it inactive for new jobs.
     * @param _enclaveAddress The address of the executor enclave to drain.
     * @dev Caller must be the owner of the executor node.
     */
    function drainExecutor(address _enclaveAddress) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
        _drainExecutor(_enclaveAddress);
    }

    function drainOperator(address _operator, bytes memory _data) external onlyRole(OPERATOR_REGISTRY_ROLE) {
        // decode the data to get the enclave address
        address enclaveAddress = abi.decode(_data, (address));
        _isValidExecutorOwner(enclaveAddress, _operator);

        _drainExecutor(enclaveAddress);
    }

    /**
     * @notice Revives a previously drained executor node.
     * @param _enclaveAddress The address of the executor enclave to revive.
     * @dev Caller must be the owner of the executor node.
     */
    function reviveExecutor(address _enclaveAddress) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
        _reviveExecutor(_enclaveAddress);
    }

    // /**
    //  * @notice Adds stake to an executor node.
    //  * @param _enclaveAddress The address of the executor enclave to add stake to.
    //  * @param _amount The amount of stake to add.
    //  * @dev Caller must be the owner of the executor node.
    //  */
    // function addExecutorStake(
    //     address _enclaveAddress,
    //     uint256 _amount
    // ) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
    //     _addExecutorStake(_amount, _enclaveAddress);
    // }

    // /**
    //  * @notice Removes stake from an executor node.
    //  * @param _enclaveAddress The address of the executor enclave to remove stake from.
    //  * @param _amount The amount of stake to remove.
    //  * @dev Caller must be the owner of the executor node.
    //  */
    // function removeExecutorStake(
    //     address _enclaveAddress,
    //     uint256 _amount
    // ) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
    //     _removeExecutorStake(_amount, _enclaveAddress);
    // }

    /**
     * @notice Allows only verified addresses to perform certain actions.
     * @param _signer The address to be verified.
     */
    function allowOnlyVerified(address _signer) external view {
        _allowOnlyVerified(_signer);
    }

    /**
     * @notice Gets the owner of a given executor node.
     * @param _enclaveAddress The address of the executor enclave.
     * @return The owner address of the executor node.
     */
    function getOwner(address _enclaveAddress) external view returns (address) {
        return executors[_enclaveAddress].owner;
    }

    //-------------------------------- external functions end ----------------------------------//

    //--------------------------------------- Executor end -----------------------------------------//

    //-------------------------------- JobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _selectExecutors(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _jobId
    ) internal returns (address[] memory selectedNodes) {
        selectedNodes = _selectNodes(_env, _noOfNodesToSelect);
        for (uint256 index = 0; index < selectedNodes.length; index++) {
            address enclaveAddress = selectedNodes[index];
            executors[enclaveAddress].activeJobs += 1;

            // lock tokens
            bytes32 lockId = keccak256(abi.encodePacked(_jobId, enclaveAddress));
            REWARD_DELEGATORS.lockTokens(
                enclaveAddress,
                lockId,
                MIN_STAKE_AMOUNT
            );

            // if jobCapacity reached or no more effective stake to lock for upcoming jobs, then delete from the tree 
            // so as to not consider this node in new jobs allocation
            if (executors[enclaveAddress].activeJobs == executors[enclaveAddress].jobCapacity ||
                REWARD_DELEGATORS.getEffectiveDelegation(enclaveAddress, keccak256("SERVERLESS_EXECUTOR")) < MIN_STAKE_AMOUNT
            )
                _deleteIfPresent(_env, enclaveAddress);
        }
    }

    function _selectNodes(
        uint8 _env,
        uint256 _noOfNodesToSelect
    ) internal view returns (address[] memory selectedNodes) {
        uint256 randomizer = uint256(keccak256(abi.encode(blockhash(block.number - 1), block.timestamp)));
        selectedNodes = _selectN(_env, randomizer, _noOfNodesToSelect);
    }

    function _unlockStakeAndReleaseExecutor(address _enclaveAddress, uint256 _jobId) internal {
        bytes32 lockId = keccak256(abi.encodePacked(_jobId, _enclaveAddress));
        REWARD_DELEGATORS.unlockTokens(_enclaveAddress, lockId);

        _releaseExecutor(_enclaveAddress);
    }

    function _releaseExecutor(address _enclaveAddress) internal {
        if (!executors[_enclaveAddress].draining) {
            uint8 env = executors[_enclaveAddress].env;
            uint256 totalDelegation = REWARD_DELEGATORS.getEffectiveDelegation(_enclaveAddress, keccak256("SERVERLESS_EXECUTOR"));
            // node might have been deleted due to max job capacity reached
            // if stakes are greater than minStakes then update the stakes for executors in tree if it already exists else add with latest stake
            if (totalDelegation >= MIN_STAKE_AMOUNT)
                _upsert(env, _enclaveAddress, uint64(totalDelegation / STAKE_ADJUSTMENT_FACTOR));
                // remove node from tree if stake falls below min level
            else _deleteIfPresent(env, _enclaveAddress);
        }

        executors[_enclaveAddress].activeJobs -= 1;
    }

    function _slashExecutor(
        address _enclaveAddress,
        uint256 _jobId,
        address _recipient
    ) internal returns (address[] memory tokens, uint256[] memory amounts) {
        // uint256 totalDelegation = REWARD_DELEGATORS.getEffectiveDelegation(_enclaveAddress, keccak256("SERVERLESS_EXECUTOR"));
        // uint256 totalComp = (totalDelegation * SLASH_PERCENT_IN_BIPS) / SLASH_MAX_BIPS;
        // // executors[_enclaveAddress].stakeAmount -= totalComp;

        // TOKEN.safeTransfer(_recipient, totalComp);

        bytes32 lockId = keccak256(abi.encodePacked(_jobId, _enclaveAddress));
        (tokens, amounts) = REWARD_DELEGATORS.slash(_enclaveAddress, lockId, _recipient);

        _releaseExecutor(_enclaveAddress);
        // return totalComp;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    /**
     * @notice Selects a number of executor nodes for job assignments.
     * @dev Executors are selected randomly based on the stake distribution.
     * @param _env The execution environment supported by the enclave.
     * @param _noOfNodesToSelect The number of nodes to select.
     * @return selectedNodes An array of selected node addresses.
     */
    function selectExecutors(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _jobId
    ) external onlyRole(JOBS_ROLE) isValidEnv(_env) returns (address[] memory selectedNodes) {
        return _selectExecutors(_env, _noOfNodesToSelect, _jobId);
    }

    /**
     * @notice Releases an executor node on job response submission, thus reducing its active jobs.
     * @dev Can only be called by an account with the `JOBS_ROLE`.
     * @param _enclaveAddress The address of the executor enclave to release.
     */
    function releaseExecutor(address _enclaveAddress) external onlyRole(JOBS_ROLE) {
        _releaseExecutor(_enclaveAddress);
    }

    function unlockStakeAndReleaseExecutor(address _enclaveAddress, uint256 _jobId) external onlyRole(JOBS_ROLE) {
        _unlockStakeAndReleaseExecutor(_enclaveAddress, _jobId);
    }

    /**
     * @notice Slashes the stake of an executor node.
     * @dev Can only be called by an account with the `JOBS_ROLE`. This function
     *      triggers a slashing penalty on the specified executor node.
     * @param _enclaveAddress The address of the executor enclave to be slashed.
     * @return The amount of stake that was slashed from the executor node.
     */
    function slashExecutor(address _enclaveAddress, uint256 _jobId) external onlyRole(JOBS_ROLE) returns (address[] memory /*tokens*/, uint256[] memory /*amounts*/) {
        return _slashExecutor(_enclaveAddress, _jobId, _msgSender());
    }

    function issueReward(
        address _enclaveAddress,
        uint256 _amount
    ) external onlyRole(JOBS_ROLE) {
        executors[_enclaveAddress].rewardAmount += _amount;
    }

    function claimReward(address _enclaveAddress) external isRewardDelegators returns (uint256 reward) {
        reward = executors[_enclaveAddress].rewardAmount;
        executors[_enclaveAddress].rewardAmount = 0;

        // transfer payout to the RewardsDelegator contract
        TOKEN.safeTransfer(_msgSender(), reward);
    }

    function getRewardInfo(address _executor) external view returns(uint256, address) {
        Executor storage executor = executors[_executor];
        return (executor.commission, executor.owner);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//
}
