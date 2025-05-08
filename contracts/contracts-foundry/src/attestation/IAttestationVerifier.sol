// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Interface for verifying attestations through enclave signatures
interface IAttestationVerifier {
    /// @notice Attestation data structure containing enclave information
    /// @param imageId Image id of the enclave
    /// @param timestampMs Attestation timestamp in milliseconds
    /// @param publicKey Public key of the attestation
    /// @param userData User data of the attestation
    struct Attestation {
        bytes32 imageId;
        uint64 timestampMs;
        bytes publicKey;
        bytes userData;
    }

    /// @notice Verifies the signature against the attestation
    /// @dev Should revert if signature verification fails
    /// @param signature ECDSA signature of the attestation data
    /// @param attestation Attestation data structure to verify
    function verify(bytes calldata signature, Attestation calldata attestation) external view;
}
