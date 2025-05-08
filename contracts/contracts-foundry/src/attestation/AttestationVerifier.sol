// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {AccessControl} from "../../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {AttestationAuther} from "./AttestationAuther.sol";
import {IAttestationVerifier} from "./IAttestationVerifier.sol";

/// @title Attestation Verifier Contract
/// @notice Handles EIP-712 based verification of signed attestations from attestation verifier enclaves
contract AttestationVerifier is AttestationAuther, IAttestationVerifier {
    /// @notice Initializes the verifier contract
    /// @param _admin Address to grant admin role
    /// @param _approver Address to grant approver role
    /// @param _revoker Address to grant revoker role
    /// @param _verifier Address of RISC Zero verifier contract
    /// @param _guestId Identifier for the zkVM guest program
    /// @param _rootKey Initial attestation root key for verification
    /// @param _maxAgeMs Maximum age (in milliseconds) for valid attestations
    /// @param _imageId Image ID for attestation verifier enclaves
    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId
    )
        AttestationAuther(
            _admin,
            _approver,
            _revoker,
            IAttestationVerifier(address(this)),
            _verifier,
            _guestId,
            _rootKey,
            _maxAgeMs,
            _imageId,
            DEFAULT_FAMILY
        )
    {}

    /// @notice EIP-712 domain separator
    bytes32 public constant DOMAIN_SEPARATOR = keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256("marlin.oyster.AttestationVerifier"),
            keccak256("1")
        )
    );

    /// @notice EIP-712 typehash for attestation struct
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes32 imageId,uint64 timestampMs,bytes publicKey,bytes userData)");

    /// @notice Verifies a signed attestation using EIP-712 signatures
    /// @param _signature ECDSA signature of the attestation
    /// @param _attestation Attestation data structure to verify
    function verify(bytes calldata _signature, Attestation calldata _attestation) external view {
        bytes32 _hashStruct = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                _attestation.imageId,
                _attestation.timestampMs,
                keccak256(_attestation.publicKey),
                keccak256(_attestation.userData)
            )
        );
        bytes32 _digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _hashStruct));

        address _signer = ECDSA.recover(_digest, _signature);
        _ensureKeyVerified(bytes32(uint256(uint160(_signer))));
    }
}
