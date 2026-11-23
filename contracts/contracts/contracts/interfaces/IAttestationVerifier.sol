// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IAttestationVerifier {
    /// @notice Attestation data signed by the attestation verifier enclave.
    /// @param imageId Image id of the enclave, computed by the attestation verifier enclave.
    /// @param timestampMs Attestation timestamp in milliseconds.
    /// @param publicKey Public key of the enclave (64 bytes, uncompressed secp256k1 without the 0x04 prefix).
    /// @param userData User data of the attestation.
    struct Attestation {
        bytes32 imageId;
        uint64 timestampMs;
        bytes publicKey;
        bytes userData;
    }

    function verify(bytes memory signature, Attestation memory attestation) external view;

    /// @param data abi.encode(signature, attestation)
    function verify(bytes memory data) external view;
}
