// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {IAttestationVerifier} from "./IAttestationVerifier.sol";

/// @title RiscZero based attestation verifier
/// @notice Contract for verifying RiscZero proofs of attestation verification
abstract contract RiscZeroVerifier {
    /// @notice Hook for getting the underlying RiscZero verifier
    function _rzvGetVerifier() internal view virtual returns (IRiscZeroVerifier);
    /// @notice Hook for setting the underlying RiscZero verifier
    function _rzvSetVerifier(IRiscZeroVerifier) internal virtual;

    /// @notice Hook for getting the expected guest id
    function _rzvGetGuestId() internal view virtual returns (bytes32);
    /// @notice Hook for setting the expected guest id
    function _rzvSetGuestId(bytes32) internal virtual;

    /// @notice Hook for getting the expected root key
    function _rzvGetRootKey() internal view virtual returns (bytes memory);
    /// @notice Hook for setting the expected root key
    function _rzvSetRootKey(bytes memory) internal virtual;

    /// @notice Hook for getting the maximum allowed age of attestations in milliseconds
    function _rzvGetMaxAgeMs() internal view virtual returns (uint256);
    /// @notice Hook for setting the maximum allowed age of attestations in milliseconds
    function _rzvSetMaxAgeMs(uint256) internal virtual;

    /// @notice Hook for authorization logic for parameter updates
    /// @dev Must be implemented by derived contracts to enforce access control
    function _rzvAuthorizeUpdate() internal virtual;

    /// @notice Thrown when attestation is too old
    error RiscZeroVerifierTooOld();
    /// @notice Thrown when public key exceeds maximum length of 255 bytes
    error RiscZeroVerifierPubkeyTooLong();
    /// @notice Thrown when user data exceeds maximum length of 65535 bytes
    error RiscZeroVerifierUserDataTooLong();

    /// @notice Emitted when verifier contract is updated
    /// @param verifier New verifier contract address
    /// @param old Previous verifier contract address
    event RiscZeroVerifierUpdatedVerifier(IRiscZeroVerifier indexed verifier, IRiscZeroVerifier indexed old);
    /// @notice Emitted when guest ID is updated
    /// @param guestId New guest ID
    /// @param old Previous guest ID
    event RiscZeroVerifierUpdatedGuestId(bytes32 indexed guestId, bytes32 indexed old);
    /// @notice Emitted when root key is updated
    /// @param rootKey New root key
    /// @param old Previous root key
    event RiscZeroVerifierUpdatedRootKey(bytes rootKey, bytes old);
    /// @notice Emitted when max age is updated
    /// @param maxAgeMs New maximum age
    /// @param old Previous maximum age
    event RiscZeroVerifierUpdatedMaxAge(uint256 maxAgeMs, uint256 old);

    /// @notice Initializes verification parameters
    /// @param _verifier Address of RiscZero verifier contract
    /// @param _guestId Expected guest image ID
    /// @param _rootKey Expected root public key
    /// @param _maxAgeMs Maximum allowed age in milliseconds
    constructor(IRiscZeroVerifier _verifier, bytes32 _guestId, bytes memory _rootKey, uint256 _maxAgeMs) {
        _updateVerifier(_verifier);
        _updateGuestId(_guestId);
        _updateRootKey(_rootKey);
        _updateMaxAge(_maxAgeMs);
    }

    /// @dev Internal setter for verifier contract
    /// @param _verifier New verifier contract address
    function _updateVerifier(IRiscZeroVerifier _verifier) internal {
        emit RiscZeroVerifierUpdatedVerifier(_verifier, _rzvGetVerifier());
        _rzvSetVerifier(_verifier);
    }

    /// @dev Internal setter for guest ID
    /// @param _guestId New guest ID
    function _updateGuestId(bytes32 _guestId) internal {
        emit RiscZeroVerifierUpdatedGuestId(_guestId, _rzvGetGuestId());
        _rzvSetGuestId(_guestId);
    }

    /// @dev Internal setter for root key
    /// @param _rootKey New root key
    function _updateRootKey(bytes memory _rootKey) internal {
        emit RiscZeroVerifierUpdatedRootKey(_rootKey, _rzvGetRootKey());
        _rzvSetRootKey(_rootKey);
    }

    /// @dev Internal setter for maximum age
    /// @param _maxAgeMs New maximum age in milliseconds
    function _updateMaxAge(uint256 _maxAgeMs) internal {
        emit RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, _rzvGetMaxAgeMs());
        _rzvSetMaxAgeMs(_maxAgeMs);
    }

    /// @notice Updates verifier contract address
    /// @dev Callable only by authorized accounts
    /// @param _verifier New verifier contract address
    function updateVerifier(IRiscZeroVerifier _verifier) external {
        _rzvAuthorizeUpdate();
        return _updateVerifier(_verifier);
    }

    /// @notice Updates guest ID
    /// @dev Callable only by authorized accounts
    /// @param _guestId New guest ID
    function updateGuestId(bytes32 _guestId) external {
        _rzvAuthorizeUpdate();
        return _updateGuestId(_guestId);
    }

    /// @notice Updates root key
    /// @dev Callable only by authorized accounts
    /// @param _rootKey New root key
    function updateRootKey(bytes calldata _rootKey) external {
        _rzvAuthorizeUpdate();
        return _updateRootKey(_rootKey);
    }

    /// @notice Updates maximum age
    /// @dev Callable only by authorized accounts
    /// @param _maxAgeMs New maximum age in milliseconds
    function updateMaxAge(uint256 _maxAgeMs) external {
        _rzvAuthorizeUpdate();
        return _updateMaxAge(_maxAgeMs);
    }

    /// @notice Verifies a RiscZero proof of attestation verification
    /// @dev Reverts if attestation is expired, pubkey too long, or verification fails
    /// @param _seal Proof seal from RiscZero
    /// @param _attestation Attestation data structure to verify
    function _verify(bytes memory _seal, IAttestationVerifier.Attestation memory _attestation) internal view {
        require(_attestation.timestampMs > block.timestamp * 1000 - _rzvGetMaxAgeMs(), RiscZeroVerifierTooOld());
        require(_attestation.publicKey.length < 256, RiscZeroVerifierPubkeyTooLong());
        require(_attestation.userData.length < 65536, RiscZeroVerifierUserDataTooLong());
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _attestation.timestampMs,
                _attestation.imageId,
                _rzvGetRootKey(),
                uint8(_attestation.publicKey.length),
                _attestation.publicKey,
                uint16(_attestation.userData.length),
                _attestation.userData
            )
        );
        _rzvGetVerifier().verify(_seal, _rzvGetGuestId(), _journalDigest);
    }
}

/// @title Default RiscZero based attestation verifier with storage
abstract contract RiscZeroVerifierDefault is RiscZeroVerifier {
    /// @notice Underlying RiscZero verifier contract
    IRiscZeroVerifier public verifier;
    /// @notice Expected guest image ID
    bytes32 public guestId;
    /// @notice Expected root public key of the attestation
    bytes public rootKey;
    /// @notice Maximum allowed age of attestations in milliseconds
    uint256 public maxAgeMs;

    /// @notice Hook for getting the underlying RiscZero verifier
    function _rzvGetVerifier() internal view virtual override returns (IRiscZeroVerifier) {
        return verifier;
    }

    /// @notice Hook for setting the underlying RiscZero verifier
    function _rzvSetVerifier(IRiscZeroVerifier _verifier) internal virtual override {
        verifier = _verifier;
    }

    /// @notice Hook for getting the expected guest id
    function _rzvGetGuestId() internal view virtual override returns (bytes32) {
        return guestId;
    }

    /// @notice Hook for setting the expected guest id
    function _rzvSetGuestId(bytes32 _guestId) internal virtual override {
        guestId = _guestId;
    }

    /// @notice Hook for getting the expected root key
    function _rzvGetRootKey() internal view virtual override returns (bytes memory) {
        return rootKey;
    }

    /// @notice Hook for setting the expected root key
    function _rzvSetRootKey(bytes memory _rootKey) internal virtual override {
        rootKey = _rootKey;
    }

    /// @notice Hook for getting the maximum allowed age of attestations in milliseconds
    function _rzvGetMaxAgeMs() internal view virtual override returns (uint256) {
        return maxAgeMs;
    }

    /// @notice Hook for setting the maximum allowed age of attestations in milliseconds
    function _rzvSetMaxAgeMs(uint256 _maxAgeMs) internal virtual override {
        maxAgeMs = _maxAgeMs;
    }
}
