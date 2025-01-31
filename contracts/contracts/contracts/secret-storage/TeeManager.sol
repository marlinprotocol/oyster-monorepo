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
import "../interfaces/IAttestationVerifier.sol";
import "./Executors.sol";
import "./SecretStore.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title TeeManager Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract TeeManager is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    using Math for uint256;

    /// @notice Thrown when the provided ERC20 token address is zero.
    error TeeManagerZeroAddressStakingToken();
    /// @notice Thrown when the provided minimum stake amount is zero.
    error TeeManagerZeroMinStakeAmount();
    /// @notice Thrown when the provided slash parameters are invalid.
    error TeeManagerInvalidSlashParams();

    /**
     * @dev Initializes the logic contract without any admins, safeguarding against takeover.
     * @param attestationVerifier The attestation verifier contract.
     * @param maxAge Maximum age for attestations.
     * @param _token The ERC20 token used for staking.
     * @param _minStakeAmount Minimum stake amount required.
     * @param _slashPercentInBips Slashing percentage in basis points.
     * @param _slashMaxBips Maximum basis points for slashing.
     * @param _env The execution environment supported by secret store enclaves.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _stakingToken,
        uint256 _minStakeAmount,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if (address(_stakingToken) == address(0)) revert TeeManagerZeroAddressStakingToken();
        if (_minStakeAmount == 0) revert TeeManagerZeroMinStakeAmount();

        STAKING_TOKEN = _stakingToken;
        MIN_STAKE_AMOUNT = _minStakeAmount;

        if(_slashPercentInBips > _slashMaxBips || _slashMaxBips > 1e6)
            revert TeeManagerInvalidSlashParams();
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
    error TeeManagerZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin and enclave images.
     * @param _admin The address of the admin.
     * @param _images Array of enclave images to initialize.
     */
    function initialize(address _admin, EnclaveImage[] memory _images) public initializer {
        if (_admin == address(0)) revert TeeManagerZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable STAKING_TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MIN_STAKE_AMOUNT;

    /// @notice an integer in the range 0-10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_PERCENT_IN_BIPS;

    /// @notice expected to be 10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_MAX_BIPS;

    /// @notice Maximum epochs accounted for slash calculation in a single iteration, to avoid integer overflow.
    /// @dev We get this value as (max(uint256) / SLASH_MAX_BIPS), where max value of uint256 is in order on 10^77 and MAX_SLASH_BIPS is 10^6.
    uint256 public constant MAX_EPOCHS_PER_ITERATION = 12;

    Executors public EXECUTORS;

    SecretStore public SECRET_STORE;

    //-------------------------------- TeeManager start ----------------------------------//

    modifier onlyExecutors() {
        if(_msgSender() != address(EXECUTORS))
            revert TeeManagerInvalidExecutors();
        _;
    }

    modifier onlySecretStore() {
        if(_msgSender() != address(SECRET_STORE))
            revert TeeManagerInvalidSecretStoreManager();
        _;
    }

    modifier onlyExecutorsOrSecretStore() {
        address caller = _msgSender();
        if(!(caller == address(SECRET_STORE) || caller == address(EXECUTORS)))
            revert TeeManagerInvalidCaller();
        _;
    }

    modifier isValidTeeNodeOwner(address _enclaveAddress) {
        _isValidTeeNodeOwner(_enclaveAddress);
        _;
    }

    function _isValidTeeNodeOwner(address _enclaveAddress) internal view {
        if (teeNodes[_enclaveAddress].owner != _msgSender())
            revert TeeManagerInvalidEnclaveOwner();
    }

    struct TeeNode {
        uint256 stakeAmount;
        address owner;
        uint8 env;
        bool draining;
    }

    // enclaveAddress => TEE node details
    mapping(address => TeeNode) public teeNodes;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.TeeManager"),
                keccak256("1")
            )
        );

    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(address owner,uint256 jobCapacity,uint256 storageCapacity,uint8 env,uint256 signTimestamp)");

    /// @notice Emitted when a new enclave is registered.
    /// @param enclaveAddress The address of the enclave.
    /// @param owner The owner of the enclave.
    /// @param storageCapacity The maximum storage of the enclave(in bytes).
    event TeeNodeRegistered(address indexed enclaveAddress, address indexed owner, uint256 jobCapacity, uint256 storageCapacity, uint8 env);

    /// @notice Emitted when an enclave is deregistered.
    /// @param enclaveAddress The address of the enclave.
    event TeeNodeDeregistered(address indexed enclaveAddress);

    /// @notice Emitted when an enclave is drained.
    /// @param enclaveAddress The address of the enclave.
    event TeeNodeDrained(address indexed enclaveAddress);

    /// @notice Emitted when an enclave is revived.
    /// @param enclaveAddress The address of the enclave.
    event TeeNodeRevived(address indexed enclaveAddress);

    /// @notice Emitted when stake is added to an enclave.
    /// @param enclaveAddress The address of the enclave.
    /// @param addedAmount The amount of stake added.
    event TeeNodeStakeAdded(address indexed enclaveAddress, uint256 addedAmount);

    /// @notice Emitted when stake is removed from an enclave.
    /// @param enclaveAddress The address of the enclave.
    /// @param removedAmount The amount of stake removed.
    event TeeNodeStakeRemoved(address indexed enclaveAddress, uint256 removedAmount);

    /// @notice Thrown when the signature timestamp has expired.
    error TeeManagerSignatureTooOld();
    /// @notice Thrown when the signer of the registration data is invalid.
    error TeeManagerInvalidSigner();
    /// @notice Thrown when attempting to register an enclave that already exists.
    error TeeManagerEnclaveAlreadyExists();
    /// @notice Thrown when attempting to drain an enclave that is already draining.
    error TeeManagerEnclaveAlreadyDraining();
    /// @notice Thrown when attempting to revive an enclave that is not draining.
    error TeeManagerEnclaveAlreadyRevived();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that is not draining.
    error TeeManagerEnclaveNotDraining();
    /// @notice Thrown when the provided enclave owner does not match the stored owner.
    error TeeManagerInvalidEnclaveOwner();
    error TeeManagerInvalidExecutors();
    error TeeManagerInvalidSecretStoreManager();
    error TeeManagerInvalidCaller();

    //-------------------------------- Admin methods start --------------------------------//

    function setExecutors(address _executorsAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        EXECUTORS = Executors(_executorsAddress);
    }

    function setSecretStore(address _secretStoreAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        SECRET_STORE = SecretStore(_secretStoreAddress);
    }

    /**
     * @notice Whitelists an enclave image for use by storage enclaves.
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

    function _registerTeeNode(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount,
        address _owner
    ) internal {
        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        if (teeNodes[enclaveAddress].owner != address(0)) 
            revert TeeManagerEnclaveAlreadyExists();

        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        // signature check
        _verifySign(enclaveAddress, _owner, _jobCapacity, _storageCapacity, _env, _signTimestamp, _signature);

        _register(enclaveAddress, _owner, _jobCapacity, _storageCapacity, _env, _stakeAmount);

        _addStake(enclaveAddress, _stakeAmount);
    }

    function _verifySign(
        address _enclaveAddress,
        address _owner,
        uint256 _jobCapacity,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE)
            revert TeeManagerSignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(REGISTER_TYPEHASH, _owner, _jobCapacity, _storageCapacity, _env, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert TeeManagerInvalidSigner();
    }

    function _register(
        address _enclaveAddress,
        address _owner,
        uint256 _jobCapacity,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) internal {
        teeNodes[_enclaveAddress].env = _env;
        teeNodes[_enclaveAddress].owner = _owner;

        EXECUTORS.registerExecutor(_enclaveAddress, _jobCapacity, _env, _stakeAmount);
        SECRET_STORE.registerSecretStore(_enclaveAddress, _storageCapacity, _env, _stakeAmount);

        emit TeeNodeRegistered(_enclaveAddress, _owner, _jobCapacity, _storageCapacity, _env);
    }

    function _drainTeeNode(address _enclaveAddress) internal {
        if (teeNodes[_enclaveAddress].draining) revert TeeManagerEnclaveAlreadyDraining();

        teeNodes[_enclaveAddress].draining = true;

        uint8 env = teeNodes[_enclaveAddress].env;
        EXECUTORS.drainExecutor(_enclaveAddress, env);
        SECRET_STORE.drainSecretStore(_enclaveAddress, env, teeNodes[_enclaveAddress].owner);

        emit TeeNodeDrained(_enclaveAddress);
    }

    function _reviveTeeNode(address _enclaveAddress) internal {
        TeeNode memory teeNode = teeNodes[_enclaveAddress];
        if (!teeNode.draining) revert TeeManagerEnclaveAlreadyRevived();

        teeNodes[_enclaveAddress].draining = false;

        // revive TEE in executors and secret store if minimum stakes are left
        if (teeNode.stakeAmount >= MIN_STAKE_AMOUNT) {
            EXECUTORS.reviveExecutor(_enclaveAddress, teeNode.env, teeNode.stakeAmount);
            SECRET_STORE.reviveSecretStore(_enclaveAddress, teeNode.env, teeNode.stakeAmount);
        }

        emit TeeNodeRevived(_enclaveAddress);
    }

    function _deregisterTeeNode(address _enclaveAddress) internal {
        TeeNode memory teeNode = teeNodes[_enclaveAddress];
        if (!teeNode.draining) revert TeeManagerEnclaveNotDraining();
        
        EXECUTORS.deregisterExecutor(_enclaveAddress);
        SECRET_STORE.deregisterSecretStore(_enclaveAddress);

        _removeStake(_enclaveAddress, teeNode.stakeAmount);

        _revokeEnclaveKey(_enclaveAddress);
        delete teeNodes[_enclaveAddress];

        emit TeeNodeDeregistered(_enclaveAddress);
    }

    function _addTeeNodeStake(uint256 _amount, address _enclaveAddress) internal {
        TeeNode memory teeNode = teeNodes[_enclaveAddress];
        uint256 updatedStake = teeNode.stakeAmount + _amount;

        if (
            !teeNode.draining &&
            updatedStake >= MIN_STAKE_AMOUNT
        ) {
            // if updated stake is greater than the min stake, then add stake in executors and secret store
            EXECUTORS.addExecutorStake(_enclaveAddress, teeNode.env, updatedStake);
            SECRET_STORE.addSecretStoreStake(_enclaveAddress, teeNode.env, updatedStake);
        }

        _addStake(_enclaveAddress, _amount);
    }

    function _removeTeeNodeStake(uint256 _amount, address _enclaveAddress) internal {
        if (!teeNodes[_enclaveAddress].draining) revert TeeManagerEnclaveNotDraining();

        EXECUTORS.removeExecutorStake(_enclaveAddress);
        SECRET_STORE.removeSecretStoreStake(_enclaveAddress);

        _removeStake(_enclaveAddress, _amount);
    }

    function _addStake(address _enclaveAddress, uint256 _amount) internal {
        teeNodes[_enclaveAddress].stakeAmount += _amount;
        // transfer stake
        STAKING_TOKEN.safeTransferFrom(teeNodes[_enclaveAddress].owner, address(this), _amount);

        emit TeeNodeStakeAdded(_enclaveAddress, _amount);
    }

    function _removeStake(address _enclaveAddress, uint256 _amount) internal {
        teeNodes[_enclaveAddress].stakeAmount -= _amount;
        // transfer stake
        STAKING_TOKEN.safeTransfer(teeNodes[_enclaveAddress].owner, _amount);

        emit TeeNodeStakeRemoved(_enclaveAddress, _amount);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    /**
     * @notice Registers a new enclave node.
     * @param _attestationSignature The attestation signature for verification.
     * @param _attestation The attestation details.
     * @param _storageCapacity The maximum storage of the enclave (in bytes).
     * @param _signTimestamp The timestamp when the signature was created.
     * @param _signature The signature to verify the registration.
     * @param _stakeAmount The amount of stake to be deposited.
     */
    function registerTeeNode(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerTeeNode(
            _attestationSignature,
            _attestation,
            _jobCapacity,
            _storageCapacity,
            _env,
            _signTimestamp,
            _signature,
            _stakeAmount,
            _msgSender()
        );
    }

    /**
     * @notice Deregisters an enclave node.
     * @param _enclaveAddress The address of the enclave to deregister.
     * @dev Caller must be the owner of the enclave node.
     */
    function deregisterTeeNode(address _enclaveAddress) external isValidTeeNodeOwner(_enclaveAddress) {
        _deregisterTeeNode(_enclaveAddress);
    }

    /**
     * @notice Drains an enclave node, making it inactive for new secret stores.
     * @param _enclaveAddress The address of the enclave to drain.
     * @dev Caller must be the owner of the enclave node.
     */
    function drainTeeNode(address _enclaveAddress) external isValidTeeNodeOwner(_enclaveAddress) {
        _drainTeeNode(_enclaveAddress);
    }

    /**
     * @notice Revives a previously drained enclave node.
     * @param _enclaveAddress The address of the enclave to revive.
     * @dev Caller must be the owner of the enclave node.
     */
    function reviveTeeNode(address _enclaveAddress) external isValidTeeNodeOwner(_enclaveAddress) {
        _reviveTeeNode(_enclaveAddress);
    }

    /**
     * @notice Adds stake to an enclave node.
     * @param _enclaveAddress The address of the enclave to add stake to.
     * @param _amount The amount of stake to add.
     * @dev Caller must be the owner of the enclave node.
     */
    function addTeeNodeStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidTeeNodeOwner(_enclaveAddress) {
        _addTeeNodeStake(_amount, _enclaveAddress);
    }

    /**
     * @notice Removes stake from an enclave node.
     * @param _enclaveAddress The address of the enclave to remove stake from.
     * @param _amount The amount of stake to remove.
     * @dev Caller must be the owner of the enclave node.
     */
    function removeTeeNodeStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidTeeNodeOwner(_enclaveAddress) {
        _removeTeeNodeStake(_amount, _enclaveAddress);
    }

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
    function getTeeNodeOwner(address _enclaveAddress) external view returns (address) {
        return teeNodes[_enclaveAddress].owner;
    }

    function getTeeNodesStake(
        address[] memory _enclaveAddresses
    ) external view returns (uint256[] memory) {
        uint256 len = _enclaveAddresses.length;
        uint256[] memory stakeAmounts = new uint256[](len);
        for (uint256 index = 0; index < len; index++)
            stakeAmounts[index] = teeNodes[_enclaveAddresses[index]].stakeAmount;

        return stakeAmounts;
    }

    function getDrainingStatus(address _enclaveAddress) external view returns (bool) {
        return teeNodes[_enclaveAddress].draining;
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- TeeManager functions end ----------------------------------//

    //------------------------------ ExecutorsRole functions start ---------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _slashExecutor(address _enclaveAddress, address _recipient) internal returns (uint256) {
        uint256 totalComp = (teeNodes[_enclaveAddress].stakeAmount * SLASH_PERCENT_IN_BIPS) / SLASH_MAX_BIPS;
        teeNodes[_enclaveAddress].stakeAmount -= totalComp;

        STAKING_TOKEN.safeTransfer(_recipient, totalComp);
    
        return totalComp;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function slashExecutor(address _enclaveAddress, address _recipient) external onlyExecutors returns (uint256) {
        return _slashExecutor(_enclaveAddress, _recipient);
    }

    //---------------------------------- external functions end ------------------------------------//

    //-------------------------------- ExecutorsRole functions end -------------------------------------//

    //------------------------------ SecretStoreRole functions start --------------------------------//

    //---------------------------------- internal functions start ----------------------------------//

    function _slashStore(
        address _enclaveAddress,
        uint256 _missedEpochsCount,
        address _recipient
    ) internal {
        uint256 stakeAmount = teeNodes[_enclaveAddress].stakeAmount;
        // compounding slashing formula: remainingStakeAmount = stakeAmount * (1 - (r/100)) ^ n
        // uint256 remainingStakeAmount = stakeAmount * ((SLASH_MAX_BIPS - SLASH_PERCENT_IN_BIPS) ** _missedEpochsCount) / (SLASH_MAX_BIPS ** _missedEpochsCount);

        // this operation will lose precision over the direct calculation because remainingStakeAmount is getting rounded off after each iteration
        uint256 remainingStakeAmount = stakeAmount;
        uint256 iterations = _missedEpochsCount / MAX_EPOCHS_PER_ITERATION;
        for (uint256 i = 0; i < iterations; i++) {
            remainingStakeAmount = remainingStakeAmount.mulDiv(((SLASH_MAX_BIPS - SLASH_PERCENT_IN_BIPS) ** MAX_EPOCHS_PER_ITERATION), (SLASH_MAX_BIPS ** MAX_EPOCHS_PER_ITERATION));
        }

        uint256 remainingEpochs = _missedEpochsCount % MAX_EPOCHS_PER_ITERATION;
        if (remainingEpochs > 0) {
            remainingStakeAmount = remainingStakeAmount.mulDiv(((SLASH_MAX_BIPS - SLASH_PERCENT_IN_BIPS) ** remainingEpochs), (SLASH_MAX_BIPS ** remainingEpochs));
        }
        
        uint256 slashAmount = stakeAmount - remainingStakeAmount;
        teeNodes[_enclaveAddress].stakeAmount = remainingStakeAmount;

        STAKING_TOKEN.safeTransfer(_recipient, slashAmount);
    }

    //---------------------------------- internal functions end ----------------------------------//

    //---------------------------------- external functions start ----------------------------------//

    function slashStore(
        address _enclaveAddress,
        uint256 _missedEpochsCount,
        address _recipient
    ) external onlySecretStore {
        _slashStore(_enclaveAddress, _missedEpochsCount, _recipient);
    }

    //---------------------------------- external functions end ----------------------------------//

    //------------------------------ SecretStoreRole functions end --------------------------------//

    //------------------------ ExecutorsOrSecretStoreRole functions start -------------------------//

    //---------------------------------- internal functions start ----------------------------------//

    function _updateTreeState(
        address _enclaveAddress
    ) internal {
        TeeNode memory teeNode = teeNodes[_enclaveAddress];
        if (!teeNode.draining) {
            // node might have been deleted due to max job capacity reached
            // if stakes are greater than minStakes then update the stakes for executors in tree if it already exists else add with latest stake
            if (teeNode.stakeAmount >= MIN_STAKE_AMOUNT) {
                EXECUTORS.upsertTreeNode(teeNode.env, _enclaveAddress, teeNode.stakeAmount);
                SECRET_STORE.upsertTreeNode(teeNode.env, _enclaveAddress, teeNode.stakeAmount);
            }
            // remove node from tree if stake falls below min level
            else {
                EXECUTORS.deleteTreeNodeIfPresent(teeNode.env, _enclaveAddress);
                SECRET_STORE.deleteTreeNodeIfPresent(teeNode.env, _enclaveAddress);
            }
        }
    }

    //---------------------------------- internal functions end ----------------------------------//

    //--------------------------------- external functions start ----------------------------------//

    function updateTreeState(
        address _enclaveAddress
    ) external onlyExecutorsOrSecretStore {
        _updateTreeState(_enclaveAddress);
    }

    //---------------------------------- external functions end ----------------------------------//

    //-------------------------- ExecutorsOrSecretStoreRole functions end ---------------------------//

}
