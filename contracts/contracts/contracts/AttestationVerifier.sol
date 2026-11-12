// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IAttestationVerifier.sol";

contract AttestationVerifier is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    UUPSUpgradeable, // public upgrade
    IAttestationVerifier // interface
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // disable all initializers and reinitializers
    // safeguard against takeover of the logic contract
    constructor() {
        _disableInitializers();
    }

    //-------------------------------- Overrides start --------------------------------//

    /// @notice Expected a non-zero image id, zero marks unverified keys.
    error AttestationVerifierImageIdZero();
    error AttestationVerifierCannotRemoveAllAdmins();

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    error AttestationVerifierNoImageProvided();
    error AttestationVerifierInitLengthMismatch();
    error AttestationVerifierInvalidAdmin();

    function initialize(bytes32[] memory images, bytes[] memory enclaveKeys, address _admin) external initializer {
        // The images and their enclave keys are whitelisted without verification that enclave keys are created within
        // the enclave. This is to initialize chain of trust and will be replaced with a more robust solution.
        if (!(images.length != 0)) revert AttestationVerifierNoImageProvided();
        if (!(images.length == enclaveKeys.length)) revert AttestationVerifierInitLengthMismatch();
        if (!(_admin != address(0))) revert AttestationVerifierInvalidAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        for (uint i = 0; i < enclaveKeys.length; i++) {
            _whitelistEnclaveImage(images[i]);
            _whitelistEnclaveKey(enclaveKeys[i], images[i]);
        }
    }

    //-------------------------------- Initializer start --------------------------------//

    //-------------------------------- Declarations start --------------------------------//

    // ImageId -> whitelisted
    mapping(bytes32 => bool) public whitelistedImages;
    // enclaveAddress -> ImageId
    mapping(address => bytes32) public verifiedKeys;

    uint256[48] private __gap_1;

    //-------------------------------- Declarations end --------------------------------//

    //-------------------------------- Admin methods start --------------------------------//

    error AttestationVerifierPubkeyLengthInvalid();

    error AttestationVerifierImageNotWhitelisted();
    error AttestationVerifierKeyNotVerified();

    event EnclaveImageWhitelisted(bytes32 indexed imageId);
    event EnclaveImageRevoked(bytes32 indexed imageId);
    event EnclaveKeyWhitelisted(address indexed enclaveAddress, bytes32 indexed imageId, bytes enclavePubKey);
    event EnclaveKeyRevoked(address indexed enclaveAddress);
    event EnclaveKeyVerified(address indexed enclaveAddress, bytes32 indexed imageId, bytes enclavePubKey);

    function _pubKeyToAddress(bytes memory pubKey) internal pure returns (address) {
        if (!(pubKey.length == 64)) revert AttestationVerifierPubkeyLengthInvalid();

        bytes32 hash = keccak256(pubKey);
        return address(uint160(uint256(hash)));
    }

    function pubKeyToAddress(bytes memory pubKey) public pure returns (address) {
        return _pubKeyToAddress(pubKey);
    }

    function _whitelistEnclaveImage(bytes32 imageId) internal returns (bool) {
        if (imageId == bytes32(0)) revert AttestationVerifierImageIdZero();
        if (whitelistedImages[imageId]) return false;

        whitelistedImages[imageId] = true;
        emit EnclaveImageWhitelisted(imageId);

        return true;
    }

    function _revokeEnclaveImage(bytes32 imageId) internal returns (bool) {
        if (!whitelistedImages[imageId]) return false;

        delete whitelistedImages[imageId];
        emit EnclaveImageRevoked(imageId);

        return true;
    }

    function _whitelistEnclaveKey(bytes memory enclavePubKey, bytes32 imageId) internal returns (bool) {
        if (!whitelistedImages[imageId]) revert AttestationVerifierImageNotWhitelisted();

        address enclaveAddress = _pubKeyToAddress(enclavePubKey);
        if (!(verifiedKeys[enclaveAddress] == bytes32(0))) return false;

        verifiedKeys[enclaveAddress] = imageId;
        emit EnclaveKeyWhitelisted(enclaveAddress, imageId, enclavePubKey);

        return true;
    }

    function _revokeEnclaveKey(address enclaveAddress) internal returns (bool) {
        if (!(verifiedKeys[enclaveAddress] != bytes32(0))) return false;

        delete verifiedKeys[enclaveAddress];
        emit EnclaveKeyRevoked(enclaveAddress);

        return true;
    }

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

    //-------------------------------- Admin methods end --------------------------------//

    //-------------------------------- Open methods start -------------------------------//

    uint256 public constant MAX_AGE = 300;

    error AttestationVerifierAttestationTooOld();

    function _verifyEnclaveKey(bytes memory signature, Attestation memory attestation) internal returns (bool) {
        bytes32 imageId = attestation.imageId;
        if (!whitelistedImages[imageId]) revert AttestationVerifierImageNotWhitelisted();
        if (!(attestation.timestampMs / 1000 > block.timestamp - MAX_AGE))
            revert AttestationVerifierAttestationTooOld();

        _verify(signature, attestation);

        address enclaveAddress = _pubKeyToAddress(attestation.publicKey);
        if (!(verifiedKeys[enclaveAddress] == bytes32(0))) return false;

        verifiedKeys[enclaveAddress] = imageId;
        emit EnclaveKeyVerified(enclaveAddress, imageId, attestation.publicKey);

        return true;
    }

    function verifyEnclaveKey(bytes memory signature, Attestation memory attestation) external returns (bool) {
        return _verifyEnclaveKey(signature, attestation);
    }

    //-------------------------------- Open methods end -------------------------------//

    //-------------------------------- Read only methods start -------------------------------//

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.AttestationVerifier"),
                keccak256("1")
            )
        );

    bytes32 private constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes32 imageId,uint64 timestampMs,bytes publicKey,bytes userData)");

    function _verify(bytes memory signature, Attestation memory attestation) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                attestation.imageId,
                attestation.timestampMs,
                keccak256(attestation.publicKey),
                keccak256(attestation.userData)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        address signer = ECDSA.recover(digest, signature);
        bytes32 imageId = verifiedKeys[signer];

        if (!(imageId != bytes32(0))) revert AttestationVerifierKeyNotVerified();
        if (!whitelistedImages[imageId]) revert AttestationVerifierImageNotWhitelisted();
    }

    function verify(bytes memory signature, Attestation memory attestation) external view {
        _verify(signature, attestation);
    }

    function verify(bytes memory data) external view {
        (bytes memory signature, Attestation memory attestation) = abi.decode(data, (bytes, Attestation));
        _verify(signature, attestation);
    }

    //-------------------------------- Read only methods end -------------------------------//
}
