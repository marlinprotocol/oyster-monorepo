// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./interfaces/IAttestationVerifier.sol";

/// @notice Contract that allows children to check if a given address belongs to a verified enclave.
/// @dev The Oyster platform works on the basis of attestations to ensure security. These attestations contain a
/// public key that can be used to extend the chain of trust to end user applications. For instance, in order to
/// verify if a message came from an enclave with a specific image, we would verify the attestation of the enclave
/// and check if the message is signed against the public key that is in the attestation, i.e. a chain of trust
/// (assuming good enclave code that does not leak the key inside it). Here, the attestation only needs to be
/// verified once, and the public key can be reused for multiple verifications later.
///
/// A common approach would be to use the `verifyEnclaveKey` function to verify the enclave key once, and use
/// the `_allowOnlyVerified` function to verify that a given signer belongs to a previously verified enclave.
///
/// Images are identified by an opaque image id computed off-chain by the attestation verifier enclave
/// (covering the PCRs of the image) and are whitelisted by that id directly.
///
/// In addition, the Auther features the concept of image families. It allows images to get tagged
/// with a family id and is paired with a family-aware `_allowOnlyVerifiedFamily` function to verify that a
/// given signer belongs to a previously verified enclave of a specific family.
contract AttestationAutherUpgradeable is
    Initializable // initializer
{
    /// @notice Attestation verifier contract that performs the verification.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IAttestationVerifier public immutable ATTESTATION_VERIFIER;

    /// @notice Maximum age of a valid attestation, in seconds.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable ATTESTATION_MAX_AGE;

    /// @notice Initializes the contract, setting the attestation verifier and max age parameters.
    /// @param attestationVerifier Address of attestation verifier contract.
    /// @param maxAge Maximum age of a valid attestation, in seconds.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IAttestationVerifier attestationVerifier, uint256 maxAge) {
        ATTESTATION_VERIFIER = attestationVerifier;
        ATTESTATION_MAX_AGE = maxAge;
    }

    /// @custom:storage-location erc7201:marlin.oyster.storage.AttestationAuther
    struct AttestationAutherStorage {
        mapping(bytes32 => bool) whitelistedImages;
        mapping(address => bytes32) verifiedKeys;
        mapping(bytes32 => mapping(bytes32 => bool)) imageFamilies;
    }

    // keccak256(abi.encode(uint256(keccak256("marlin.oyster.storage.AttestationAuther")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AttestationAutherStorageLocation =
        0xc17b4b708b6f44255c20913a9d97a05300b670342c71fe5ae5b617bd4db55000;

    function _getAttestationAutherStorage() private pure returns (AttestationAutherStorage storage $) {
        assembly {
            $.slot := AttestationAutherStorageLocation
        }
    }

    /// @notice Expected a pubkey with length equal to 64.
    /// @notice Expected a non-zero image id, zero marks unverified keys.
    error AttestationAutherImageIdZero();
    error AttestationAutherPubkeyLengthInvalid();
    /// @notice Expected the enclave image to be whitelisted.
    error AttestationAutherImageNotWhitelisted();
    /// @notice Expected the enclave image to be in a specific family.
    error AttestationAutherImageNotInFamily();
    /// @notice Expected the enclave key to be verified.
    error AttestationAutherKeyNotVerified();
    /// @notice Expected the attestation to be recent.
    error AttestationAutherAttestationTooOld();
    /// @notice Expected the arrays to have equal lengths.
    error AttestationAutherMismatchedLengths();

    /// @notice Emitted when enclave image `imageId` is whitelisted.
    event EnclaveImageWhitelisted(bytes32 indexed imageId);
    /// @notice Emitted when enclave image `imageId` is revoked.
    event EnclaveImageRevoked(bytes32 indexed imageId);
    /// @notice Emitted when enclave image `imageId` is added to `family`.
    event EnclaveImageAddedToFamily(bytes32 indexed imageId, bytes32 family);
    /// @notice Emitted when enclave image `imageId` is removed from `family`.
    event EnclaveImageRemovedFromFamily(bytes32 indexed imageId, bytes32 family);
    /// @notice Emitted when enclave key `enclaveAddress` is whitelisted against enclave image `imageId`.
    event EnclaveKeyWhitelisted(address indexed enclaveAddress, bytes32 indexed imageId, bytes enclavePubKey);
    /// @notice Emitted when enclave key `enclaveAddress` is revoked.
    event EnclaveKeyRevoked(address indexed enclaveAddress);
    /// @notice Emitted when enclave key `enclaveAddress` is verified against enclave image `imageId`.
    event EnclaveKeyVerified(address indexed enclaveAddress, bytes32 indexed imageId, bytes enclavePubKey);

    /// @notice Initializes the contract by whitelisting the provided enclave images.
    /// @param images Ids of the enclave images to be whitelisted.
    function __AttestationAuther_init_unchained(bytes32[] memory images) internal onlyInitializing {
        for (uint256 i = 0; i < images.length; i++) {
            _whitelistEnclaveImage(images[i]);
        }
    }

    /// @notice Initializes the contract by whitelisting the provided enclave images and adding them
    /// to the respective families.
    /// @param images Ids of the enclave images to be whitelisted.
    /// @param families Corresponding family for each enclave images.
    function __AttestationAuther_init_unchained(
        bytes32[] memory images,
        bytes32[] memory families
    ) internal onlyInitializing {
        if (!(images.length == families.length)) revert AttestationAutherMismatchedLengths();
        for (uint256 i = 0; i < images.length; i++) {
            _whitelistEnclaveImage(images[i]);
            _addEnclaveImageToFamily(images[i], families[i]);
        }
    }

    /// @notice Computes the address corresponding to a given public key.
    /// @param pubKey Public key for which the address needs to be computed.
    /// @return Address corresponding to `pubKey`.
    function _pubKeyToAddress(bytes memory pubKey) internal pure returns (address) {
        if (!(pubKey.length == 64)) revert AttestationAutherPubkeyLengthInvalid();

        bytes32 hash = keccak256(pubKey);
        return address(uint160(uint256(hash)));
    }

    /// @notice Whitelist an enclave image without verifying any attestations.
    /// May emit a `EnclaveImageWhitelisted` event.
    /// @param imageId Id of the image to be whitelisted.
    /// @return true if the image was freshly whitelisted, false otherwise.
    function _whitelistEnclaveImage(bytes32 imageId) internal virtual returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        if (imageId == bytes32(0)) revert AttestationAutherImageIdZero();
        if ($.whitelistedImages[imageId]) return false;

        $.whitelistedImages[imageId] = true;
        emit EnclaveImageWhitelisted(imageId);

        return true;
    }

    /// @notice Revoke an enclave image.
    /// May emit a `EnclaveImageRevoked` event.
    /// @param imageId Image to be revoked.
    /// @return true if the image was freshly revoked, false otherwise.
    function _revokeEnclaveImage(bytes32 imageId) internal virtual returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        if (!$.whitelistedImages[imageId]) return false;

        delete $.whitelistedImages[imageId];
        emit EnclaveImageRevoked(imageId);

        return true;
    }

    /// @notice Add an enclave image to a given family.
    /// May emit a `EnclaveImageAddedToFamily` event.
    /// @param imageId Image to be added to family.
    /// @param family Family to add the image to.
    /// @return true if the image was freshly added to the family, false otherwise.
    function _addEnclaveImageToFamily(bytes32 imageId, bytes32 family) internal virtual returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        if (!($.imageFamilies[family][imageId] == false)) return false;

        $.imageFamilies[family][imageId] = true;
        emit EnclaveImageAddedToFamily(imageId, family);

        return true;
    }

    /// @notice Remove an enclave image from a given family.
    /// May emit a `EnclaveImageRemovedFromFamily` event.
    /// @param imageId Image to be removed from family.
    /// @param family Family to remove the image from.
    /// @return true if the image was freshly removed from the family, false otherwise.
    function _removeEnclaveImageFromFamily(bytes32 imageId, bytes32 family) internal virtual returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        if (!($.imageFamilies[family][imageId] == true)) return false;

        $.imageFamilies[family][imageId] = false;
        emit EnclaveImageRemovedFromFamily(imageId, family);

        return true;
    }

    /// @notice Whitelist an enclave key against a given enclave image without verifying any attestations.
    /// May emit a `EnclaveKeyWhitelisted` event.
    /// @param enclavePubKey Enclave key to be whitelisted.
    /// @param imageId Image to be whitelisted against.
    /// @return true if the key was freshly whitelisted against the image, false otherwise.
    function _whitelistEnclaveKey(bytes memory enclavePubKey, bytes32 imageId) internal virtual returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        if (!$.whitelistedImages[imageId]) revert AttestationAutherImageNotWhitelisted();

        address enclaveAddress = _pubKeyToAddress(enclavePubKey);
        if (!($.verifiedKeys[enclaveAddress] == bytes32(0))) return false;

        $.verifiedKeys[enclaveAddress] = imageId;
        emit EnclaveKeyWhitelisted(enclaveAddress, imageId, enclavePubKey);

        return true;
    }

    /// @notice Revoke an enclave key.
    /// May emit a `EnclaveKeyRevoked` event.
    /// @param enclaveAddress Enclave whose key is to be revoked.
    /// @return true if the key was freshly revoked, false otherwise.
    function _revokeEnclaveKey(address enclaveAddress) internal virtual returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        if (!($.verifiedKeys[enclaveAddress] != bytes32(0))) return false;

        delete $.verifiedKeys[enclaveAddress];
        emit EnclaveKeyRevoked(enclaveAddress);

        return true;
    }

    /// @notice Verify an enclave key using an attestation.
    /// May emit a `EnclaveKeyVerified` event.
    /// @param signature Signature from a valid attestation verifier enclave.
    /// @param attestation Attestation from the enclave to be verified.
    /// @return true if the key was freshly verified, false otherwise.
    function _verifyEnclaveKey(
        bytes memory signature,
        IAttestationVerifier.Attestation memory attestation
    ) internal virtual returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        bytes32 imageId = attestation.imageId;
        if (!$.whitelistedImages[imageId]) revert AttestationAutherImageNotWhitelisted();
        if (!(attestation.timestampMs / 1000 > block.timestamp - ATTESTATION_MAX_AGE))
            revert AttestationAutherAttestationTooOld();

        ATTESTATION_VERIFIER.verify(signature, attestation);

        address enclaveAddress = _pubKeyToAddress(attestation.publicKey);
        if (!($.verifiedKeys[enclaveAddress] == bytes32(0))) return false;

        $.verifiedKeys[enclaveAddress] = imageId;
        emit EnclaveKeyVerified(enclaveAddress, imageId, attestation.publicKey);

        return true;
    }

    /// @notice Verify an enclave key using an attestation.
    /// May emit a `EnclaveKeyVerified` event.
    /// @param signature Signature from a valid attestation verifier enclave.
    /// @param attestation Attestation from the enclave to be verified.
    /// @return true if the key was freshly verified, false otherwise.
    function verifyEnclaveKey(
        bytes memory signature,
        IAttestationVerifier.Attestation memory attestation
    ) external returns (bool) {
        return _verifyEnclaveKey(signature, attestation);
    }

    /// @notice Returns only if the key is from a verified enclave, reverts otherwise.
    /// @param key Key to be verified.
    function _allowOnlyVerified(address key) internal view virtual {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        bytes32 imageId = $.verifiedKeys[key];
        if (!(imageId != bytes32(0))) revert AttestationAutherKeyNotVerified();
        if (!$.whitelistedImages[imageId]) revert AttestationAutherImageNotWhitelisted();
    }

    /// @notice Returns only if the key is from a verified enclave of the given family, reverts otherwise.
    /// @param key Key to be verified.
    /// @param family Expected family of the enclave.
    function _allowOnlyVerifiedFamily(address key, bytes32 family) internal view virtual {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        bytes32 imageId = $.verifiedKeys[key];
        if (!(imageId != bytes32(0))) revert AttestationAutherKeyNotVerified();
        if (!$.whitelistedImages[imageId]) revert AttestationAutherImageNotWhitelisted();
        if (!($.imageFamilies[family][imageId])) revert AttestationAutherImageNotInFamily();
    }

    /// @notice Check if a given image is whitelisted.
    /// @param _imageId Image being checked.
    /// @return true if `_imageId` is whitelisted, false otherwise.
    function isImageWhitelisted(bytes32 _imageId) external view returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        return $.whitelistedImages[_imageId];
    }

    /// @notice Get the image against which a key is verified.
    /// @param _key Key whose image need to be queried.
    /// @return Image id of the image against which the key is verified.
    function getVerifiedKey(address _key) external view returns (bytes32) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        return $.verifiedKeys[_key];
    }

    /// @notice Check is a given image is part of a given family.
    /// @param imageId Image being checked.
    /// @param family Expected family of the image.
    /// @return true if `imageId` is part of `family`, false otherwise.
    function isImageInFamily(bytes32 imageId, bytes32 family) external view returns (bool) {
        AttestationAutherStorage storage $ = _getAttestationAutherStorage();

        return $.imageFamilies[family][imageId];
    }
}
