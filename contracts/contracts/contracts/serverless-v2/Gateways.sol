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
import "./Jobs.sol";

/**
 * @title Gateways Contract
 * @notice Manages gateway enclave registration, staking, and chain management on the common chain.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract Gateways is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Expected a non-zero address for the token.
    error GatewaysZeroAddressToken();

    /**
     * @notice Constructor for initializing the logic contract without any admins.
     * @dev Safeguard against the further takeover of the logic contract.
     *      Regarding basis points, if slash percent is 0.1%, then _slashPercentInBips
     *      can be represented as 1, whereas _slashMaxBips will be 1000(=100%).
     * @param attestationVerifier The contract responsible for verifying attestations.
     * @param maxAge The maximum age of an attestation.
     * @param _token The ERC20 token used for staking(POND).
     * @param _deregisterOrUnstakeTimeout Timeout duration for deregistering or unstaking.
     * @param _slashPercentInBips The percentage of slash in basis points.
     * @param _slashMaxBips The maximum basis points for slashing.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        uint256 _deregisterOrUnstakeTimeout,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if (address(_token) == address(0)) revert GatewaysZeroAddressToken();
        TOKEN = _token;

        DRAINING_TIME_DURATION = _deregisterOrUnstakeTimeout;
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

    /// @notice Expected a non-zero address for the admin.
    error GatewaysZeroAddressAdmin();

    /**
     * @notice Initializes the Gateways contract.
     * @dev This function is called only once and initializes the upgradeable state variables.
     * @param _admin The address to be granted the DEFAULT_ADMIN_ROLE.
     * @param _images The initial enclave images to be whitelisted.
     */
    function initialize(address _admin, EnclaveImage[] memory _images) public initializer {
        if (_admin == address(0)) revert GatewaysZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @notice The ERC20 token used for staking(POND).
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @notice The duration for draining before deregistration or unstaking.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable DRAINING_TIME_DURATION;

    /// @notice The slashing percentage in basis points(an integer in the range 0-10^6)
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_PERCENT_IN_BIPS;

    /// @notice The maximum slashing basis points(expected to be 10^6)
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_MAX_BIPS;

    bytes32 public constant GATEWAY_JOBS_ROLE = keccak256("GATEWAY_JOBS_ROLE");

    //-------------------------------- Gateway start --------------------------------//

    modifier isValidGatewayOwner(address _enclaveAddress, address _owner) {
        if (gateways[_enclaveAddress].owner != _owner) revert GatewaysNotGatewayOwner();
        _;
    }

    struct RequestChain {
        address relayAddress;
        address relaySubscriptionsAddress;
        string httpRpcUrl;
        string wsRpcUrl;
    }

    mapping(uint256 => RequestChain) public requestChains;

    struct Gateway {
        address owner;
        uint256[] chainIds;
        uint256 stakeAmount;
        bool draining;
        uint256 drainStartTime;
    }

    // enclaveAddress => Gateway
    mapping(address => Gateway) public gateways;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Gateways"),
                keccak256("1")
            )
        );

    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(address owner,uint256[] chainIds,uint256 signTimestamp)");
    bytes32 private constant ADD_CHAINS_TYPEHASH = keccak256("AddChains(uint256[] chainIds,uint256 signTimestamp)");
    bytes32 private constant REMOVE_CHAINS_TYPEHASH =
        keccak256("RemoveChains(uint256[] chainIds,uint256 signTimestamp)");

    /// @notice Event emitted when a gateway is registered.
    /// @param enclaveAddress The address of the registered enclave.
    /// @param owner The owner of the gateway.
    /// @param chainIds The request chain IDs associated with the gateway.
    event GatewayRegistered(address indexed enclaveAddress, address indexed owner, uint256[] chainIds);

    /// @notice Event emitted when a gateway is deregistered.
    /// @param enclaveAddress The address of the deregistered enclave.
    event GatewayDeregistered(address indexed enclaveAddress);

    /// @notice Event emitted when stake is added to a gateway.
    /// @param enclaveAddress The address of the gateway.
    /// @param addedAmount The amount of stake added.
    event GatewayStakeAdded(address indexed enclaveAddress, uint256 addedAmount);

    /// @notice Event emitted when a new request chain is added globally.
    /// @param chainId The ID of the chain.
    /// @param relayAddress The Relay contract address on the chain.
    /// @param relaySubscriptionsAddress The RelaySubscriptions contract address on the chain.
    /// @param httpRpcUrl The HTTP RPC URL of the chain.
    /// @param wsRpcUrl The WebSocket RPC URL of the chain.
    event ChainAddedGlobal(
        uint256 chainId,
        address relayAddress,
        address relaySubscriptionsAddress,
        string httpRpcUrl,
        string wsRpcUrl
    );

    /// @notice Event emitted when a request chain is removed globally.
    /// @param chainId The ID of the removed chain.
    event ChainRemovedGlobal(uint256 chainId);

    /// @notice Event emitted when a gateway enclave starts supporting a new request chain.
    /// @param enclaveAddress The address of the gateway.
    /// @param chainId The ID of the added chain.
    event ChainAdded(address indexed enclaveAddress, uint256 chainId);

    /// @notice Event emitted when a gateway stops supporting a request chain.
    /// @param enclaveAddress The address of the gateway.
    /// @param chainId The ID of the removed chain.
    event ChainRemoved(address indexed enclaveAddress, uint256 chainId);

    /// @notice Event emitted when a gateway is drained.
    /// @param enclaveAddress The address of the drained gateway.
    event GatewayDrained(address indexed enclaveAddress);

    /// @notice Event emitted when a gateway is revived.
    /// @param enclaveAddress The address of the revived gateway.
    event GatewayRevived(address indexed enclaveAddress);

    /// @notice Event emitted when the deposited stake is removed by a gateway.
    /// @param enclaveAddress The address of the gateway.
    /// @param removedAmount The amount of stake removed.
    event GatewayStakeRemoved(address indexed enclaveAddress, uint256 removedAmount);

    /// @notice Thrown when a global chain already exists.
    /// @param chainId The ID of the chain.
    error GatewaysGlobalChainAlreadyExists(uint256 chainId);
    /// @notice Thrown when an invalid signer is detected.
    error GatewaysInvalidSigner();
    /// @notice Thrown when a gateway already exists for the given enclave address, during registration.
    error GatewaysGatewayAlreadyExists();
    /// @notice Thrown when an unsupported chain is detected.
    error GatewaysUnsupportedChain();
    /// @notice Thrown when a signature is too old.
    error GatewaysSignatureTooOld();
    /// @notice Thrown when an invalid length is provided for arrays.
    error GatewaysInvalidLength();
    /// @notice Thrown when an empty list of requested chains is provided.
    error GatewaysEmptyRequestedChains();
    /// @notice Thrown when a chain already exists in the gateway.
    /// @param chainId The ID of the chain.
    error GatewaysChainAlreadyExists(uint256 chainId);
    /// @notice Thrown when the chain list for a gateway is empty.
    error GatewaysEmptyChainlist();
    /// @notice Thrown when a chain is not found in the gateway.
    /// @param chainId The ID of the chain.
    error GatewaysChainNotFound(uint256 chainId);
    /// @notice Thrown when the msg.sender isn't the gateway owner.
    error GatewaysNotGatewayOwner();
    /// @notice Thrown when a gateway is already draining.
    error GatewaysAlreadyDraining();
    /// @notice Thrown when a gateway drain is pending.
    error GatewaysDrainPending();
    /// @notice Thrown when a gateway is not draining.
    error GatewaysNotDraining();
    /// @notice Thrown when a gateway is already revived.
    error GatewaysAlreadyRevived();

    //-------------------------------- Admin methods start --------------------------------//

    function _addChainGlobal(uint256[] memory _chainIds, RequestChain[] memory _requestChains) internal {
        if (_chainIds.length == 0 || _chainIds.length != _requestChains.length) revert GatewaysInvalidLength();
        for (uint256 index = 0; index < _requestChains.length; index++) {
            RequestChain memory reqChain = _requestChains[index];
            uint256 chainId = _chainIds[index];
            if(requestChains[chainId].relayAddress != address(0))
                revert GatewaysGlobalChainAlreadyExists(chainId);
            requestChains[chainId] = reqChain;

            emit ChainAddedGlobal(
                chainId,
                reqChain.relayAddress,
                reqChain.relaySubscriptionsAddress,
                reqChain.httpRpcUrl,
                reqChain.wsRpcUrl
            );
        }
    }

    function _removeChainGlobal(uint256[] memory _chainIds) internal {
        if (_chainIds.length == 0) revert GatewaysInvalidLength();
        for (uint256 index = 0; index < _chainIds.length; index++) {
            uint256 chainId = _chainIds[index];
            delete requestChains[chainId];

            emit ChainRemovedGlobal(chainId);
        }
    }

    /**
     * @notice Whitelists an enclave image by adding its PCR values.
     * @dev Can only be called by an account with the DEFAULT_ADMIN_ROLE.
     * @param PCR0 The first PCR value of the enclave image.
     * @param PCR1 The second PCR value of the enclave image.
     * @param PCR2 The third PCR value of the enclave image.
     * @return bytes32 The unique identifier (hash) of the whitelisted enclave image.
     * @return bool Whether the whitelisting was successful.
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
     * @dev Can only be called by an account with the DEFAULT_ADMIN_ROLE.
     * @param imageId The unique identifier (hash) of the enclave image to revoke.
     * @return bool Whether the revocation was successful.
     */
    function revokeEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(imageId);
    }

    /**
     * @notice Adds multiple request chains globally to the system.
     * @param _chainIds The IDs of the chains to be added.
     * @param _requestChains The corresponding request chains to be added.
     * @dev Can only be called by an account with the DEFAULT_ADMIN_ROLE.
     */
    function addChainGlobal(
        uint256[] memory _chainIds,
        RequestChain[] memory _requestChains
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addChainGlobal(_chainIds, _requestChains);
    }

    /**
     * @notice Removes multiple request chains globally from the system.
     * @param _chainIds The IDs of the chains to be removed.
     * @dev Can only be called by an account with the DEFAULT_ADMIN_ROLE.
     */
    function removeChainGlobal(uint256[] memory _chainIds) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _removeChainGlobal(_chainIds);
    }

    //-------------------------------- Admin methods end ----------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount,
        uint256 _signTimestamp,
        address _owner
    ) internal {
        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        // signature check
        _verifyRegisterSign(_owner, _chainIds, _signTimestamp, _signature, enclaveAddress);

        if (gateways[enclaveAddress].owner != address(0)) revert GatewaysGatewayAlreadyExists();

        for (uint256 index = 0; index < _chainIds.length; index++) {
            if (requestChains[_chainIds[index]].relayAddress == address(0)) revert GatewaysUnsupportedChain();
        }

        _register(enclaveAddress, _owner, _chainIds);

        _addStake(enclaveAddress, _stakeAmount);
    }

    function _verifyRegisterSign(
        address _owner,
        uint256[] memory _chainIds,
        uint256 _signTimestamp,
        bytes memory _signature,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE) revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(REGISTER_TYPEHASH, _owner, keccak256(abi.encodePacked(_chainIds)), _signTimestamp)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert GatewaysInvalidSigner();
    }

    function _register(address _enclaveAddress, address _owner, uint256[] memory _chainIds) internal {
        gateways[_enclaveAddress].owner = _owner;
        gateways[_enclaveAddress].chainIds = _chainIds;

        emit GatewayRegistered(_enclaveAddress, _owner, _chainIds);
    }

    function _drainGateway(address _enclaveAddress) internal {
        if (gateways[_enclaveAddress].draining) revert GatewaysAlreadyDraining();

        gateways[_enclaveAddress].draining = true;
        gateways[_enclaveAddress].drainStartTime = block.timestamp;

        emit GatewayDrained(_enclaveAddress);
    }

    function _deregisterGateway(address _enclaveAddress) internal {
        if (!gateways[_enclaveAddress].draining) revert GatewaysNotDraining();

        if (block.timestamp <= gateways[_enclaveAddress].drainStartTime + DRAINING_TIME_DURATION)
            revert GatewaysDrainPending();

        _removeStake(_enclaveAddress, gateways[_enclaveAddress].stakeAmount);

        _revokeEnclaveKey(_enclaveAddress);
        delete gateways[_enclaveAddress];

        emit GatewayDeregistered(_enclaveAddress);
    }

    function _reviveGateway(address _enclaveAddress) internal {
        if (!gateways[_enclaveAddress].draining) revert GatewaysAlreadyRevived();
        gateways[_enclaveAddress].draining = false;
        gateways[_enclaveAddress].drainStartTime = 0;

        emit GatewayRevived(_enclaveAddress);
    }

    function _addGatewayStake(address _enclaveAddress, uint256 _amount) internal {
        _addStake(_enclaveAddress, _amount);
    }

    function _removeGatewayStake(address _enclaveAddress, uint256 _amount) internal {
        if (!gateways[_enclaveAddress].draining) revert GatewaysNotDraining();

        if (block.timestamp <= gateways[_enclaveAddress].drainStartTime + DRAINING_TIME_DURATION)
            revert GatewaysDrainPending();

        _removeStake(_enclaveAddress, _amount);
    }

    function _addChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestamp,
        address _enclaveAddress
    ) internal {
        if (_chainIds.length == 0) revert GatewaysEmptyRequestedChains();

        _verifyAddChainsSign(_signature, _chainIds, _signTimestamp, _enclaveAddress);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _addChain(_chainIds[index], _enclaveAddress);
        }
    }

    function _verifyAddChainsSign(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestamp,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE) revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(ADD_CHAINS_TYPEHASH, keccak256(abi.encodePacked(_chainIds)), _signTimestamp)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert GatewaysInvalidSigner();

        _allowOnlyVerified(signer);
    }

    function _addChain(uint256 _chainId, address _enclaveAddress) internal {
        if (requestChains[_chainId].relayAddress == address(0)) revert GatewaysUnsupportedChain();

        uint256[] memory chainIdList = gateways[_enclaveAddress].chainIds;
        for (uint256 index = 0; index < chainIdList.length; index++) {
            if (chainIdList[index] == _chainId) revert GatewaysChainAlreadyExists(_chainId);
        }
        gateways[_enclaveAddress].chainIds.push(_chainId);

        emit ChainAdded(_enclaveAddress, _chainId);
    }

    function _removeChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestamp,
        address _enclaveAddress
    ) internal {
        if (_chainIds.length == 0) revert GatewaysEmptyRequestedChains();

        _verifyRemoveChainsSign(_signature, _chainIds, _signTimestamp, _enclaveAddress);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _removeChain(_chainIds[index], _enclaveAddress);
        }
    }

    function _verifyRemoveChainsSign(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestamp,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE) revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(REMOVE_CHAINS_TYPEHASH, keccak256(abi.encodePacked(_chainIds)), _signTimestamp)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert GatewaysInvalidSigner();

        _allowOnlyVerified(signer);
    }

    function _removeChain(uint256 _chainId, address _enclaveAddress) internal {
        uint256[] memory chainIdList = gateways[_enclaveAddress].chainIds;
        uint256 len = chainIdList.length;
        if (len == 0) revert GatewaysEmptyChainlist();

        uint256 index = 0;
        for (; index < len; index++) {
            if (chainIdList[index] == _chainId) break;
        }

        if (index == len) revert GatewaysChainNotFound(_chainId);
        if (index != len - 1) gateways[_enclaveAddress].chainIds[index] = gateways[_enclaveAddress].chainIds[len - 1];

        gateways[_enclaveAddress].chainIds.pop();

        emit ChainRemoved(_enclaveAddress, _chainId);
    }

    function _addStake(address _enclaveAddress, uint256 _amount) internal {
        gateways[_enclaveAddress].stakeAmount += _amount;
        // transfer stake
        TOKEN.safeTransferFrom(gateways[_enclaveAddress].owner, address(this), _amount);

        emit GatewayStakeAdded(_enclaveAddress, _amount);
    }

    function _removeStake(address _enclaveAddress, uint256 _amount) internal {
        gateways[_enclaveAddress].stakeAmount -= _amount;
        // transfer stake
        TOKEN.safeTransfer(gateways[_enclaveAddress].owner, _amount);

        emit GatewayStakeRemoved(_enclaveAddress, _amount);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Registers a new gateway with the given attestation, chains, and stake amount.
     * @param _attestationSignature The signature for the attestation.
     * @param _attestation The attestation data.
     * @param _chainIds The chain IDs to be associated with the gateway.
     * @param _signature The signature to authorize the registration.
     * @param _stakeAmount The amount of tokens to be staked.
     * @param _signTimestamp The timestamp when the signature was created.
     */
    function registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount,
        uint256 _signTimestamp
    ) external {
        _registerGateway(
            _attestationSignature,
            _attestation,
            _chainIds,
            _signature,
            _stakeAmount,
            _signTimestamp,
            _msgSender()
        );
    }

    /**
     * @notice Deregisters an existing gateway.
     * @param _enclaveAddress The address of the enclave to be deregistered.
     */
    function deregisterGateway(address _enclaveAddress) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _deregisterGateway(_enclaveAddress);
    }

    /**
     * @notice Initiates the draining process for the gateway, allowing the owner to eventually remove their stake and deregister.
     * @param _enclaveAddress The address of the enclave to be drained.
     */
    function drainGateway(address _enclaveAddress) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _drainGateway(_enclaveAddress);
    }

    /**
     * @notice Revives a gateway that was previously marked for draining.
     * @param _enclaveAddress The address of the enclave to be revived.
     */
    function reviveGateway(address _enclaveAddress) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _reviveGateway(_enclaveAddress);
    }

    /**
     * @notice Adds stake to an existing gateway.
     * @param _enclaveAddress The address of the enclave to which stake is being added.
     * @param _amount The amount of stake to be added.
     */
    function addGatewayStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _addGatewayStake(_enclaveAddress, _amount);
    }

    /**
     * @notice Removes stake from an existing gateway.
     * @param _enclaveAddress The address of the enclave from which stake is being removed.
     * @param _amount The amount of stake to be removed.
     */
    function removeGatewayStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _removeGatewayStake(_enclaveAddress, _amount);
    }

    /**
     * @notice Adds chains to the specified gateway.
     * @param _signature The signature to authorize the addition of chains.
     * @param _chainIds The chain IDs to be added.
     * @param _signTimestamp The timestamp when the signature was created.
     * @param _enclaveAddress The address of the enclave to which chains are being added.
     */
    function addChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestamp,
        address _enclaveAddress
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _addChains(_signature, _chainIds, _signTimestamp, _enclaveAddress);
    }

    /**
     * @notice Removes chains from the specified gateway.
     * @param _signature The signature to authorize the removal of chains.
     * @param _chainIds The chain IDs to be removed.
     * @param _signTimestamp The timestamp when the signature was created.
     * @param _enclaveAddress The address of the enclave from which chains are being removed.
     */
    function removeChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestamp,
        address _enclaveAddress
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _removeChains(_signature, _chainIds, _signTimestamp, _enclaveAddress);
    }

    /**
     * @notice Checks if a specific chain is supported by the gateway system.
     * @param _reqChainId The ID of the chain to check.
     * @return bool indicating whether the chain is supported.
     */
    function isChainSupported(uint256 _reqChainId) external view returns (bool) {
        return (requestChains[_reqChainId].relayAddress != address(0));
    }

    /**
     * @notice Retrieves the list of chain IDs associated with a specific gateway.
     * @param _enclaveAddress The address of the enclave.
     * @return uint256[] Array of chain IDs associated with the gateway.
     */
    function getGatewayChainIds(address _enclaveAddress) external view returns (uint256[] memory) {
        return gateways[_enclaveAddress].chainIds;
    }

    /**
     * @notice Ensures that the specified enclave address is verified.
     * @param _enclaveAddress The address of the enclave to verify.
     */
    function allowOnlyVerified(address _enclaveAddress) external view {
        _allowOnlyVerified(_enclaveAddress);
    }

    /**
     * @notice Retrieves the owner of the specified gateway.
     * @param _enclaveAddress The address of the enclave.
     * @return address The owner of the gateway.
     */
    function getOwner(address _enclaveAddress) external view returns (address) {
        return gateways[_enclaveAddress].owner;
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Gateway end --------------------------------//

    //-------------------------------- GatewayJobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _slashOnReassignGateway(address _oldGateway, address _recipient) internal returns (uint256) {
        uint256 totalComp = (gateways[_oldGateway].stakeAmount * SLASH_PERCENT_IN_BIPS) / SLASH_MAX_BIPS;
        gateways[_oldGateway].stakeAmount -= totalComp;

        // transfer comp to reporter gateway
        TOKEN.safeTransfer(_recipient, totalComp);
        return totalComp;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //------------------------------- external functions start ---------------------------------//

    /**
     * @notice Slashes a portion of the stake from the old gateway when it is reassigned.
     * @param _oldGateway The address of the old gateway being slashed.
     * @return uint256 The amount of tokens slashed and transferred.
     * @dev Can only be called by an account with the GATEWAY_JOBS_ROLE.
     */
    function slashOnReassignGateway(address _oldGateway) external onlyRole(GATEWAY_JOBS_ROLE) returns (uint256) {
        return _slashOnReassignGateway(_oldGateway, _msgSender());
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- GatewayJobsContract functions end --------------------------------//
}
