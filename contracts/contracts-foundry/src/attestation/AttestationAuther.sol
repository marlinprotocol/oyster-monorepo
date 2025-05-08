// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {AccessControl} from "../../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {IAttestationVerifier} from "./IAttestationVerifier.sol";
import {RiscZeroVerifier, RiscZeroVerifierDefault} from "./RiscZeroVerifier.sol";
import {VerifiedKeys, VerifiedKeysDefault} from "./VerifiedKeys.sol";

/// @title Attestation Auther Contract
/// @notice Enclave key tracker for user contracts. Provides attestation verification, key management and image management.
contract AttestationAuther is AccessControl, RiscZeroVerifierDefault, VerifiedKeysDefault {
    /// @notice Role for approvers who can approve new images
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");

    /// @notice Role for revokers who can revoke existing images
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    IAttestationVerifier public attestationVerifier;

    /// @dev Error thrown when attestation exceeds maximum allowed age
    error AttestationAutherTooOld();

    /// @dev Error thrown when public key has invalid format/length
    error AttestationAutherPubkeyInvalid();

    /// @notice Initializes the contract with roles and verification parameters
    /// @param _admin Address to grant admin role
    /// @param _approver Address to grant approver role
    /// @param _revoker Address to grant revoker role
    /// @param _attestationVerifier Address of attestation verifier contract
    /// @param _verifier Address of RISC Zero verifier contract
    /// @param _guestId Identifier for the zkVM guest program
    /// @param _rootKey Initial root key for verification
    /// @param _maxAgeMs Maximum age (in milliseconds) for valid attestations
    /// @param _imageId Expected image ID for enclave verification
    /// @param _family Image family
    /// @dev Sets up role-based access control and initializes parent contracts
    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IAttestationVerifier _attestationVerifier,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family
    ) RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs) VerifiedKeys(_imageId, _family) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APPROVER_ROLE, _approver);
        _grantRole(REVOKER_ROLE, _revoker);
        attestationVerifier = _attestationVerifier;
    }

    /// @inheritdoc RiscZeroVerifier
    /// @dev Restricts updates to DEFAULT_ADMIN_ROLE
    function _rzvAuthorizeUpdate() internal virtual override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @inheritdoc VerifiedKeys
    /// @dev Restricts approvals to APPROVER_ROLE
    function _vkAuthorizeApprove() internal virtual override onlyRole(APPROVER_ROLE) {}

    /// @inheritdoc VerifiedKeys
    /// @dev Restricts revocations to REVOKER_ROLE
    function _vkAuthorizeRevoke() internal virtual override onlyRole(REVOKER_ROLE) {}

    /// @notice Transforms a public key into a Ethereum address format
    /// @param _pubkey The raw 64-byte public key to transform
    /// @return Address-formatted hash of the public key
    /// @dev Hashes the public key with keccak256 and truncates to 20 bytes
    function _vkTransformPubkey(bytes memory _pubkey) internal virtual override returns (bytes32) {
        require(_pubkey.length == 64, AttestationAutherPubkeyInvalid());

        return keccak256(_pubkey) & 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff;
    }

    /// @notice Verifies an enclave using RISC Zero proof verification
    /// @param _seal ZK proof seal
    /// @param _attestation Attestation data structure to verify
    function verifyEnclaveRiscZero(bytes calldata _seal, IAttestationVerifier.Attestation calldata _attestation)
        external
    {
        _verify(_seal, _attestation);
        _setKeyVerified(_attestation.publicKey, _attestation.imageId);
    }

    /// @notice Verifies an enclave using a signed attestation
    /// @param _signature Signature
    /// @param _attestation Attestation to verify
    function verifyEnclaveSignature(bytes calldata _signature, IAttestationVerifier.Attestation calldata _attestation)
        external
    {
        require(_attestation.timestampMs > block.timestamp * 1000 - maxAgeMs, AttestationAutherTooOld());
        attestationVerifier.verify(_signature, _attestation);
        _setKeyVerified(_attestation.publicKey, _attestation.imageId);
    }
}
