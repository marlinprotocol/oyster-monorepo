// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {AccessControl} from "../../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {RiscZeroVerifier, RiscZeroVerifierDefault} from "../attestation/RiscZeroVerifier.sol";
import {VerifiedKeys, VerifiedKeysDefault} from "../attestation/VerifiedKeys.sol";
import {IAttestationVerifier} from "../attestation/IAttestationVerifier.sol";

/// @title KMS Root Contract
/// @notice Manages list of KMS servers allowed to decrypt root key
contract KmsRoot is AccessControl, RiscZeroVerifierDefault, VerifiedKeysDefault {
    /// @notice Approver role, for approving images
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    /// @notice Revoker role, for revoking images
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    /// @notice Thrown when input length is invalid (public key must be 64 bytes)
    error KmsRootLengthInvalid();

    /// @notice Initializes the KmsRoot contract
    /// @param _admin Address of the contract admin
    /// @param _approver Address of the image approver
    /// @param _revoker Address of the image revoker
    /// @param _verifier Address of the RISC Zero verifier contract
    /// @param _guestId Guest ID of the RISC Zero program
    /// @param _rootKey Initial root key
    /// @param _maxAgeMs Maximum age allowed for attestation timestamps
    /// @param _imageId Image ID for verification
    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId
    ) RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs) VerifiedKeys(_imageId, DEFAULT_FAMILY) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APPROVER_ROLE, _approver);
        _grantRole(REVOKER_ROLE, _revoker);
    }

    /// @notice Authorizes the admin to execute parameter updates
    function _rzvAuthorizeUpdate() internal virtual override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Authorize the approver to approve images
    function _vkAuthorizeApprove() internal virtual override onlyRole(APPROVER_ROLE) {}

    /// @notice Authorize the revoker to revoke images
    function _vkAuthorizeRevoke() internal virtual override onlyRole(REVOKER_ROLE) {}

    /// @notice Tranform the public key into an address before storage
    function _vkTransformPubkey(bytes memory _pubkey) internal virtual override returns (bytes32) {
        require(_pubkey.length == 64, KmsRootLengthInvalid());

        return keccak256(_pubkey) & 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff;
    }

    /// @notice Verifies a KMS attestation
    /// @param _seal Proof seal from RiscZero
    /// @param _attestation Attestation data structure to verify
    /// @dev Verifies the attestation and marks the derived address as verified if successful
    function verify(bytes calldata _seal, IAttestationVerifier.Attestation calldata _attestation) external {
        _verify(_seal, _attestation);
        _setKeyVerified(_attestation.publicKey, _attestation.imageId);
    }

    /// @notice Check if a key is verified
    /// @dev Checks both key and image status
    /// @param _addr Address to verify
    function isVerified(address _addr) external view returns (bool) {
        bytes32 _imageId = _vkGetEnclaveImage(bytes32(uint256(uint160(_addr))));
        return _imageId != bytes32(0) && _vkGetImageFamily(_imageId) != bytes32(0);
    }
}
