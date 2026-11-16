// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./AttestationAutherUpgradeable.sol";

contract AttestationAutherSampleUpgradeable is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable // auther
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // disable all initializers and reinitializers
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    error AttestationAutherSampleNoImageProvided();
    error AttestationAutherSampleInvalidAdmin();

    function initialize(bytes32[] memory images, address _admin) external initializer {
        if (!(images.length != 0)) revert AttestationAutherSampleNoImageProvided();
        if (!(_admin != address(0))) revert AttestationAutherSampleInvalidAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    function initializeWithFamilies(
        bytes32[] memory images,
        bytes32[] memory families,
        address _admin
    ) external initializer {
        if (!(images.length != 0)) revert AttestationAutherSampleNoImageProvided();
        if (!(_admin != address(0))) revert AttestationAutherSampleInvalidAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(images, families);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer start --------------------------------//

    //-------------------------------- Admin methods start --------------------------------//

    function whitelistEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _whitelistEnclaveImage(imageId);
    }

    function revokeEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(imageId);
    }

    function whitelistEnclaveKey(
        bytes memory enclavePubKey,
        bytes32 imageId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _whitelistEnclaveKey(enclavePubKey, imageId);
    }

    function revokeEnclaveKey(address enclaveAddress) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveKey(enclaveAddress);
    }

    function addEnclaveImageToFamily(
        bytes32 imageId,
        bytes32 family
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _addEnclaveImageToFamily(imageId, family);
    }

    function removeEnclaveImageFromFamily(
        bytes32 imageId,
        bytes32 family
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _removeEnclaveImageFromFamily(imageId, family);
    }

    //-------------------------------- Admin methods end --------------------------------//

    //-------------------------------- Open methods start -------------------------------//

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.AttestationAutherSample"),
                keccak256("1")
            )
        );

    struct Message {
        string message;
    }
    bytes32 private constant MESSAGE_TYPEHASH = keccak256("Message(string message)");

    function verify(bytes memory signature, string memory message) external view {
        bytes32 hashStruct = keccak256(abi.encode(MESSAGE_TYPEHASH, keccak256(bytes(message))));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        address signer = ECDSA.recover(digest, signature);

        _allowOnlyVerified(signer);
    }

    function verifyFamily(bytes memory signature, string memory message, bytes32 family) external view {
        bytes32 hashStruct = keccak256(abi.encode(MESSAGE_TYPEHASH, keccak256(bytes(message))));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        address signer = ECDSA.recover(digest, signature);

        _allowOnlyVerifiedFamily(signer, family);
    }

    //-------------------------------- Open methods end -------------------------------//
}
