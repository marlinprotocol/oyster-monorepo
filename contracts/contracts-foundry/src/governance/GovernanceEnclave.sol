// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/* Contracts */
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title GovernanceEnclave
/// @notice Manages KMS, PCR, and RPC URL configurations for Governance Enclave.
///         This contract stores configurations that are queried by the Governance contract during proposal processing
///         or read by the Governance Enclave deployed through the Governance contract.
///         Key features include KMS path and root server public key management, PCR configuration and image ID generation,
///         multi-chain RPC URL and token address configuration management, and enclave/KMS signature verification.
contract GovernanceEnclave is
    Initializable,
    ContextUpgradeable,
    ERC165Upgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    using ECDSA for bytes32;

    // ========== Errors ==========
    error GovernanceEnclave__OnlyAdmin();
    error GovernanceEnclave__InvalidAddress();
    error GovernanceEnclave__InvalidPubKeyLength();
    error GovernanceEnclave__InvalidKMSRootServerPubKey();
    error GovernanceEnclave__InvalidEnclavePubKeyLength();
    error GovernanceEnclave__InvalidPCR();
    error GovernanceEnclave__SameImageId();
    error GovernanceEnclave__InvalidMaxRpcUrlsPerChain();
    error GovernanceEnclave__InvalidChainId();
    error GovernanceEnclave__InvalidInputLength();
    error GovernanceEnclave__InvalidRpcUrl();
    error GovernanceEnclave__InvalidRpcUrlIndex();
    error GovernanceEnclave__MaxRpcUrlsPerChainReached();
    error GovernanceEnclave__OnlyConfigSetter();

    // ========== Types ==========

    struct PCR {
        bytes pcr0;
        bytes pcr1;
        bytes pcr2;
    }

    struct PCRConfig {
        PCR pcr;
        bytes32 imageId;
    }

    struct TokenNetworkConfig {
        bytes32 chainHash; // sha256(abi.encode(chainId, rpcUrls))
        address tokenAddress;
        string[] rpcUrls;
    }

    // ========== Constants ==========

    bytes32 public constant GOVERNANCE_ADMIN_CONFIG_SETTER_ROLE = keccak256("GOVERNANCE_ADMIN_CONFIG_SETTER_ROLE");

    // ========== State Variables ==========

    uint256[500] private __gap0;

    // KMS and PCR Configuration
    bytes public kmsRootServerPubKey;
    PCRConfig public pcrConfig;

    // Network Configuration
    bytes32 private networkHash;
    uint256[] public supportedChainIds;
    uint256 public maxRPCUrlsPerChain;
    mapping(uint256 chainId => TokenNetworkConfig config) public tokenNetworkConfigs;

    uint256[50] private __gap1;

    // ========== Events ==========

    // KMS Events
    event KMSRootServerPubKeySet(bytes kmsRootServerPubKey);

    // PCR Events
    event PCRConfigSet(bytes pcr0, bytes pcr1, bytes pcr2, bytes32 imageId);

    // Network Configuration Events
    event MaxRpcUrlsPerChainSet(uint256 maxRPCUrlsPerChain);
    event NetworkConfigSet(uint256 indexed chainId, address tokenAddress, string[] rpcUrls, bytes32 networkHash);

    // RPC URL Management Events
    event RpcUrlUpdated(uint256 indexed chainId, uint256[] indexes, string[] newRpcUrls);
    event RpcUrlAdded(uint256 indexed chainId, string[] newRpcUrls);
    event RpcUrlRemoved(uint256 indexed chainId, uint256[] indexes);

    // ========== Modifiers ==========

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), GovernanceEnclave__OnlyAdmin());
        _;
    }

    modifier onlyConfigSetter() {
        require(hasRole(GOVERNANCE_ADMIN_CONFIG_SETTER_ROLE, _msgSender()), GovernanceEnclave__OnlyConfigSetter());
        _;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address /*account*/ ) internal view override onlyAdmin {}

    //-------------------------------- Overrides ends --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    constructor() initializer {}

    function initialize(
        address _admin,
        bytes calldata _kmsRootServerPubKey,
        bytes calldata _pcr0,
        bytes calldata _pcr1,
        bytes calldata _pcr2,
        uint256 _maxRPCUrlsPerChain
    ) external initializer {
        require(_admin != address(0), GovernanceEnclave__InvalidAddress());

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        // Grant admin role
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        // Set KMS root server key
        _setKMSRootServerKey(_kmsRootServerPubKey);

        // Set PCR config
        _setPCRConfig(_pcr0, _pcr1, _pcr2);

        // Set Max RPC URLs per Chain
        _setMaxRPCUrlsPerChain(_maxRPCUrlsPerChain);
    }

    //-------------------------------- Initializer ends --------------------------------//

    //-------------------------------- Admin starts --------------------------------//

    /// @notice Sets the KMS Root Server public key for signature verification
    /// @dev This public key is used to verify KMS signatures during proposal result submission
    /// @param _kmsRootServerPubKey The public key of the KMS root server
    function setKMSRootServerKey(bytes calldata _kmsRootServerPubKey) external onlyAdmin {
        _setKMSRootServerKey(_kmsRootServerPubKey);
    }

    function _setKMSRootServerKey(bytes calldata _kmsRootServerPubKey) internal {
        require(_kmsRootServerPubKey.length > 0, GovernanceEnclave__InvalidKMSRootServerPubKey());
        kmsRootServerPubKey = _kmsRootServerPubKey;
        emit KMSRootServerPubKeySet(_kmsRootServerPubKey);
    }

    /// @notice Sets the PCR configuration (PCR0, PCR1, PCR2) and generates the corresponding image ID
    /// @dev This configuration is used for enclave verification and must be unique from the current configuration
    /// @param _pcr0 The PCR0 value for enclave verification
    /// @param _pcr1 The PCR1 value for enclave verification
    /// @param _pcr2 The PCR2 value for enclave verification
    function setPCRConfig(bytes calldata _pcr0, bytes calldata _pcr1, bytes calldata _pcr2) external onlyAdmin {
        _setPCRConfig(_pcr0, _pcr1, _pcr2);
    }

    function _setPCRConfig(bytes calldata _pcr0, bytes calldata _pcr1, bytes calldata _pcr2) internal {
        require(_pcr0.length > 0 && _pcr1.length > 0 && _pcr2.length > 0, GovernanceEnclave__InvalidPCR());
        bytes32 imageIdGenerated = _generateImageId(_pcr0, _pcr1, _pcr2);
        require(imageIdGenerated != pcrConfig.imageId, GovernanceEnclave__SameImageId());

        pcrConfig.pcr = PCR({pcr0: _pcr0, pcr1: _pcr1, pcr2: _pcr2});
        pcrConfig.imageId = imageIdGenerated;
        emit PCRConfigSet(_pcr0, _pcr1, _pcr2, imageIdGenerated);
    }

    /// @notice Sets the maximum number of RPC URLs allowed per chain
    /// @dev This limit prevents excessive RPC URL storage and ensures efficient network configuration management
    /// @param _maxRPCUrlsPerChain The maximum number of RPC URLs allowed per chain
    function setMaxRPCUrlsPerChain(uint256 _maxRPCUrlsPerChain) external onlyAdmin {
        _setMaxRPCUrlsPerChain(_maxRPCUrlsPerChain);
    }

    function _setMaxRPCUrlsPerChain(uint256 _maxRPCUrlsPerChain) internal {
        require(_maxRPCUrlsPerChain > 0, GovernanceEnclave__InvalidMaxRpcUrlsPerChain());
        maxRPCUrlsPerChain = _maxRPCUrlsPerChain;
        emit MaxRpcUrlsPerChainSet(_maxRPCUrlsPerChain);
    }

    /// @notice Add or update NetworkConfig for the specified chainId
    /// @dev If the chainId is not in supportedChainIds, it will be added.
    /// @param _chainId The chain ID for which the network config is being set
    /// @param _tokenAddress The address of the token contract on the specified chain
    ///          If the token address is set to address(0), the chainId will be removed from supportedChainIds
    /// @param _rpcUrls An array of RPC URLs for the specified chain
    function setNetworkConfig(uint256 _chainId, address _tokenAddress, string[] calldata _rpcUrls) public onlyAdmin {
        require(_chainId > 0, GovernanceEnclave__InvalidChainId());
        require(_rpcUrls.length > 0, GovernanceEnclave__InvalidRpcUrl());
        require(_rpcUrls.length <= maxRPCUrlsPerChain, GovernanceEnclave__MaxRpcUrlsPerChainReached());

        // If _tokenAddress is address(0), remove the chainId from supportedChainIds
        if (_tokenAddress == address(0)) {
            _removeChainId(_chainId);
            // Clear the token network config for this chainId
            delete tokenNetworkConfigs[_chainId];
            networkHash = _calcNetworkHash();
            emit NetworkConfigSet(_chainId, _tokenAddress, _rpcUrls, networkHash);
            return;
        }

        bool chainIdExists = _isChainIdSupported(_chainId);

        // If the chainId is not supported, add it to the supportedChainIds
        if (!chainIdExists) {
            supportedChainIds.push(_chainId);
        }

        // Update the token network config
        bytes32 chainHash = sha256(abi.encode(_chainId, _rpcUrls));
        tokenNetworkConfigs[_chainId] =
            TokenNetworkConfig({chainHash: chainHash, tokenAddress: _tokenAddress, rpcUrls: _rpcUrls});

        networkHash = _calcNetworkHash();

        emit NetworkConfigSet(_chainId, _tokenAddress, _rpcUrls, networkHash);
    }

    function _calcNetworkHash() internal view returns (bytes32) {
        bytes32 currentHash = bytes32(0);
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            uint256 chainId = supportedChainIds[i];
            bytes32 chainHash = tokenNetworkConfigs[chainId].chainHash;
            currentHash = sha256(abi.encode(currentHash, chainHash));
        }
        return currentHash;
    }

    function _isChainIdSupported(uint256 _chainId) internal view returns (bool) {
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            if (supportedChainIds[i] == _chainId) return true;
        }
        return false;
    }

    /// @notice Remove a chainId from the supportedChainIds array
    /// @dev This function removes the specified chainId from the supportedChainIds array
    /// @param _chainId The chain ID to remove from supported chain IDs
    function _removeChainId(uint256 _chainId) internal {
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            if (supportedChainIds[i] == _chainId) {
                // Move the last element to the position of the element to delete
                supportedChainIds[i] = supportedChainIds[supportedChainIds.length - 1];
                // Remove the last element
                supportedChainIds.pop();
                break;
            }
        }
    }

    /// @notice Adds new RPC URLs to the end of the array for the specified chainId
    /// @param _chainId The chain ID for which to add RPC URLs
    /// @param _newRpcUrls Array of new RPC URLs to add
    function addRpcUrls(uint256 _chainId, string[] calldata _newRpcUrls) external onlyAdmin {
        require(_chainId > 0, GovernanceEnclave__InvalidChainId());
        require(_isChainIdSupported(_chainId), GovernanceEnclave__InvalidChainId());
        require(_newRpcUrls.length > 0, GovernanceEnclave__InvalidRpcUrl());

        string[] storage currentRpcUrls = tokenNetworkConfigs[_chainId].rpcUrls;
        require(
            currentRpcUrls.length + _newRpcUrls.length <= maxRPCUrlsPerChain,
            GovernanceEnclave__MaxRpcUrlsPerChainReached()
        );

        // Validate new URLs and add them
        for (uint256 i = 0; i < _newRpcUrls.length; ++i) {
            require(bytes(_newRpcUrls[i]).length > 0, GovernanceEnclave__InvalidRpcUrl());
            currentRpcUrls.push(_newRpcUrls[i]);
        }

        // Recalculate chainHash and networkHash
        bytes32 chainHash = sha256(abi.encode(_chainId, currentRpcUrls));
        tokenNetworkConfigs[_chainId].chainHash = chainHash;
        networkHash = _calcNetworkHash();

        emit RpcUrlAdded(_chainId, _newRpcUrls);
    }

    /// @notice Removes RPC URLs at specific indexes for the specified chainId
    /// @param _chainId The chain ID for which to remove RPC URLs
    /// @param _indexes Array of indexes to remove
    function removeRpcUrlsAtIndexes(uint256 _chainId, uint256[] calldata _indexes) external onlyAdmin {
        require(_chainId > 0, GovernanceEnclave__InvalidChainId());
        require(_isChainIdSupported(_chainId), GovernanceEnclave__InvalidChainId());
        require(_indexes.length > 0, GovernanceEnclave__InvalidRpcUrl());

        string[] storage currentRpcUrls = tokenNetworkConfigs[_chainId].rpcUrls;
        require(currentRpcUrls.length > _indexes.length, GovernanceEnclave__InvalidRpcUrl());

        // Validate indexes are within bounds
        for (uint256 i = 0; i < _indexes.length; ++i) {
            require(_indexes[i] < currentRpcUrls.length, GovernanceEnclave__InvalidRpcUrlIndex());
        }

        // Remove URLs by swapping with last element and popping
        for (uint256 i = 0; i < _indexes.length; ++i) {
            uint256 idxToRemove = _indexes[i];
            // Move the last element to the position of the element to delete
            currentRpcUrls[idxToRemove] = currentRpcUrls[currentRpcUrls.length - 1];
            // Remove the last element
            currentRpcUrls.pop();
        }

        // Recalculate chainHash and networkHash
        bytes32 chainHash = sha256(abi.encode(_chainId, currentRpcUrls));
        tokenNetworkConfigs[_chainId].chainHash = chainHash;
        networkHash = _calcNetworkHash();

        emit RpcUrlRemoved(_chainId, _indexes);
    }

    /// @notice Updates specific RPC URLs at given indexes for the specified chainId
    /// @param _chainId The chain ID for which to update RPC URLs
    /// @param _indexes Array of indexes to update
    /// @param _newRpcUrls Array of new RPC URLs to set at the corresponding indexes
    function updateRpcUrlsAtIndexes(uint256 _chainId, uint256[] calldata _indexes, string[] calldata _newRpcUrls)
        external
        onlyAdmin
    {
        require(_chainId > 0, GovernanceEnclave__InvalidChainId());
        require(_isChainIdSupported(_chainId), GovernanceEnclave__InvalidChainId());
        require(_indexes.length == _newRpcUrls.length, GovernanceEnclave__InvalidInputLength());
        require(_indexes.length > 0, GovernanceEnclave__InvalidRpcUrl());

        string[] storage currentRpcUrls = tokenNetworkConfigs[_chainId].rpcUrls;
        require(currentRpcUrls.length > 0, GovernanceEnclave__InvalidRpcUrl());

        // Validate indexes and update URLs
        for (uint256 i = 0; i < _indexes.length; ++i) {
            require(_indexes[i] < currentRpcUrls.length, GovernanceEnclave__InvalidRpcUrlIndex());
            require(bytes(_newRpcUrls[i]).length > 0, GovernanceEnclave__InvalidRpcUrl());
            currentRpcUrls[_indexes[i]] = _newRpcUrls[i];
        }

        // Recalculate chainHash and networkHash
        bytes32 chainHash = sha256(abi.encode(_chainId, currentRpcUrls));
        tokenNetworkConfigs[_chainId].chainHash = chainHash;
        networkHash = _calcNetworkHash();

        emit RpcUrlUpdated(_chainId, _indexes, _newRpcUrls);
    }

    //-------------------------------- Admin ends --------------------------------//

    //-------------------------------- Verify start -------------------------------//

    /// @notice Verifies a KMS signature for enclave public key derivation
    /// @dev This function reconstructs the URI and verifies the signature against the KMS root server public key
    /// @param _imageId The image ID used in the KMS path
    /// @param _enclavePubKey The enclave public key to verify
    /// @param _kmsSig The KMS signature to verify
    /// @param _proposalId The proposal ID used as the KMS path
    /// @return isValid True if the signature is valid, false otherwise
    function verifyKMSSig(bytes32 _imageId, bytes calldata _enclavePubKey, bytes calldata _kmsSig, bytes32 _proposalId)
        public
        view
        returns (bool)
    {
        // Reconstruct URI (must match the format signed by the KMS)
        // Check: https://github.com/marlinprotocol/oyster-monorepo/tree/master/kms/root-server#public-endpoints
        string memory uri = string(
            abi.encodePacked(
                "/derive/secp256k1/public?image_id=", _toHexStringWithNoPrefix(_imageId), "&path=", _toHexStringWithNoPrefix(_proposalId)
            )
        );

        // Combine URI and binary public key
        bytes memory message = abi.encodePacked(bytes(uri), _enclavePubKey);

        // Hash the message
        bytes32 messageHash = sha256(message);

        // Recover signer address
        return messageHash.recover(_kmsSig) == _pubKeyToAddress(kmsRootServerPubKey);
    }

    function verifyEnclaveSig(bytes memory _enclavePubKey, bytes memory _enclaveSig, bytes memory message)
        external
        pure
        returns (bool)
    {
        // Reconstruct the message to verify
        bytes32 digest = sha256(message);

        // Recover the address from the signature
        address recoveredAddress = digest.recover(_enclaveSig);

        // Convert the public key to address
        address enclaveAddress = _pubKeyToAddress(_enclavePubKey);

        // Compare the recovered address with the enclave address
        return recoveredAddress == enclaveAddress;
    }

    //-------------------------------- Verify ends --------------------------------//

    //-------------------------------- Getters start -------------------------------//

    function getImageId() external view returns (bytes32) {
        return pcrConfig.imageId;
    }

    function getNetworkHash() external view returns (bytes32) {
        return networkHash;
    }

    function getSupportedChainIdsLength() external view returns (uint256) {
        return supportedChainIds.length;
    }

    /// @notice Returns the complete array of supported chain IDs
    /// @dev This allows external contracts and users to get all supported chains in a single call
    /// @return chainIds Array of all supported chain IDs
    function getSupportedChainIds() external view returns (uint256[] memory) {
        return supportedChainIds;
    }

    /// @notice Checks if a specific chain ID is supported
    /// @param _chainId The chain ID to check
    /// @return isSupported True if the chain is supported, false otherwise
    function isChainSupported(uint256 _chainId) external view returns (bool) {
        return _isChainIdSupported(_chainId);
    }

    function getTokenNetworkConfig(uint256 _chainId) external view returns (TokenNetworkConfig memory) {
        return tokenNetworkConfigs[_chainId];
    }

    /// @notice Returns the PCR configuration including all PCR values and the image ID
    /// @dev This allows external contracts to verify the current PCR configuration
    /// @return pcr0 The PCR0 value
    /// @return pcr1 The PCR1 value
    /// @return pcr2 The PCR2 value
    /// @return imageId The generated image ID from the PCR values
    function getPCRConfig() external view returns (bytes memory pcr0, bytes memory pcr1, bytes memory pcr2, bytes32 imageId) {
        return (pcrConfig.pcr.pcr0, pcrConfig.pcr.pcr1, pcrConfig.pcr.pcr2, pcrConfig.imageId);
    }

    //-------------------------------- Getters end -------------------------------//

    //-------------------------------- Helpers start -------------------------------//

    /// @dev Converts bytes32 to a hex string without the '0x' prefix
    /// @return hexString The hex string representation without '0x' prefix
    function _toHexStringWithNoPrefix(bytes32 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    /// @dev Converts a public key to an Ethereum address
    /// @return address The Ethereum address derived from the public key
    function _pubKeyToAddress(bytes memory _pubKey) internal pure returns (address) {
        require(_pubKey.length == 64, GovernanceEnclave__InvalidPubKeyLength());

        bytes32 pubKeyHash = keccak256(_pubKey);
        return address(uint160(uint256(pubKeyHash)));
    }

    /// @dev Generates an image ID from PCR values for enclave verification
    /// @return imageId The generated image ID for enclave verification
    function _generateImageId(bytes memory _pcr0, bytes memory _pcr1, bytes memory _pcr2)
        internal
        pure
        returns (bytes32)
    {
        uint32 bitflags = uint32((1 << 0) | (1 << 1) | (1 << 2) | (1 << 16));
        bytes memory pcr16 = new bytes(48);
        return sha256(abi.encodePacked(bitflags, _pcr0, _pcr1, _pcr2, pcr16));
    }

    //-------------------------------- Helpers end -------------------------------//
}
