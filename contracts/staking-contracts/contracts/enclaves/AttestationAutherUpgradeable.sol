// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IAttestationVerifier.sol";

contract AttestationAutherUpgradeable is
    Initializable  // initializer
{
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IAttestationVerifier public immutable ATTESTATION_VERIFIER;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable ATTESTATION_MAX_AGE;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IAttestationVerifier attestationVerifier, uint256 maxAge) {
        ATTESTATION_VERIFIER = attestationVerifier;
        ATTESTATION_MAX_AGE = maxAge;
    }

    struct EnclaveImage {
        bytes PCR0;
        bytes PCR1;
        bytes PCR2;
    }

    mapping(bytes32 => EnclaveImage) private whitelistedImages;
    mapping(address => bytes32) private verifiedKeys;

    uint256[48] private __gap;

    event EnclaveImageWhitelisted(bytes32 indexed imageId, bytes PCR0, bytes PCR1, bytes PCR2);
    event EnclaveImageRevoked(bytes32 indexed imageId);
    event EnclaveKeyWhitelisted(bytes indexed enclavePubKey, bytes32 indexed imageId);
    event EnclaveKeyRevoked(bytes indexed enclavePubKey);
    event EnclaveKeyVerified(bytes indexed enclavePubKey, bytes32 indexed imageId);

    function __AttestationAuther_init_unchained(EnclaveImage[] memory images) internal onlyInitializing {
        for (uint256 i = 0; i < images.length; i++) {
            _whitelistEnclaveImage(images[i]);
        }
    }

    function _pubKeyToAddress(bytes memory pubKey) internal pure returns (address) {
        require(pubKey.length == 64, "Invalid public key length");

        bytes32 hash = keccak256(pubKey);
        return address(uint160(uint256(hash)));
    }

    function _whitelistEnclaveImage(EnclaveImage memory image) internal returns(bytes32) {
        require(
            image.PCR0.length == 48 &&
            image.PCR1.length == 48 &&
            image.PCR2.length == 48,
            "AA:WI-PCR values must be 48 bytes"
        );

        bytes32 imageId = keccak256(abi.encodePacked(image.PCR0, image.PCR1, image.PCR2));
        require(whitelistedImages[imageId].PCR0.length == 0, "AA:WI-image already whitelisted");
        whitelistedImages[imageId] = EnclaveImage(image.PCR0, image.PCR1, image.PCR2);
        emit EnclaveImageWhitelisted(imageId, image.PCR0, image.PCR1, image.PCR2);
        return imageId;
    }

    function _revokeEnclaveImage(bytes32 imageId) internal {
        require(whitelistedImages[imageId].PCR0.length != 0, "AA:RI-Image not whitelisted");

        delete whitelistedImages[imageId];
        emit EnclaveImageRevoked(imageId);
    }

    function _whitelistEnclaveKey(bytes memory enclavePubKey, bytes32 imageId) internal {
        require(whitelistedImages[imageId].PCR0.length != 0, "AA:WK-Image not whitelisted");
        address enclaveKey = _pubKeyToAddress(enclavePubKey);
        require(verifiedKeys[enclaveKey] == bytes32(0), "AA:WK-Enclave key already verified");

        verifiedKeys[enclaveKey] = imageId;
        emit EnclaveKeyWhitelisted(enclavePubKey, imageId);
    }

    function _revokeEnclaveKey(bytes memory enclavePubKey) internal {
        address enclaveKey = _pubKeyToAddress(enclavePubKey);
        require(verifiedKeys[enclaveKey] != bytes32(0), "AA:RK-Enclave key not verified");

        delete verifiedKeys[enclaveKey];
        emit EnclaveKeyRevoked(enclavePubKey);
    }

    // add enclave key of a whitelisted image to the list of verified enclave keys
    function _verifyKey(
        bytes memory signature,
        bytes memory enclavePubKey,
        bytes32 imageId,
        uint256 enclaveCPUs,
        uint256 enclaveMemory,
        uint256 timestampInMilliseconds
    ) internal {
        require(
            whitelistedImages[imageId].PCR0.length != 0,
            "AA:VK-Enclave image to verify not whitelisted"
        );
        address enclaveKey = _pubKeyToAddress(enclavePubKey);
        require(
            verifiedKeys[enclaveKey] == bytes32(0),
            "AA:VK-Enclave key already verified"
        );
        require(timestampInMilliseconds / 1000 > block.timestamp - ATTESTATION_MAX_AGE , "AA:VK-Attestation too old");

        EnclaveImage memory image = whitelistedImages[imageId];
        ATTESTATION_VERIFIER.verify(
            signature,
            enclavePubKey,
            image.PCR0,
            image.PCR1,
            image.PCR2,
            enclaveCPUs,
            enclaveMemory,
            timestampInMilliseconds
        );

        verifiedKeys[enclaveKey] = imageId;
        emit EnclaveKeyVerified(enclavePubKey, imageId);
    }

    function verifyKey(
        bytes memory signature,
        bytes memory enclavePubKey,
        bytes32 imageId,
        uint256 enclaveCPUs,
        uint256 enclaveMemory,
        uint256 timestampInMilliseconds
    ) external {
        return _verifyKey(signature, enclavePubKey, imageId, enclaveCPUs, enclaveMemory, timestampInMilliseconds);
    }

    function _allowOnlyVerified(address key) internal view {
        bytes32 imageId = verifiedKeys[key];
        require(
            imageId != bytes32(0),
            "AA:AOV-Enclave key must be verified"
        );
        require(
            whitelistedImages[imageId].PCR0.length != 0,
            "AA:AOV-Source image must be whitelisted"
        );
    }

    function getWhitelistedImage(bytes32 _imageId) external view returns (EnclaveImage memory) {
        return whitelistedImages[_imageId];
    }

    function getVerifiedKey(address _key) external view returns (bytes32) {
        return verifiedKeys[_key];
    }
}
