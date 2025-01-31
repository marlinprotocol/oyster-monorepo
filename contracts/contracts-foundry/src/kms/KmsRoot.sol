// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

/// @title KMS Root Contract
/// @notice Manages list of KMS servers allowed to decrypt root key
contract KmsRoot is Ownable {
    /// @notice Maximum age allowed for attestation timestamps
    uint256 public immutable MAX_AGE;

    /// @notice RISC Zero verifier contract interface
    IRiscZeroVerifier public verifier;
    /// @notice Image ID for RISC Zero verification
    bytes32 public imageId;
    /// @notice Platform Configuration Registers (PCRs) for attestation
    bytes public pcrs;
    /// @notice Root key of the attestation (should be the Nitro root key)
    bytes public rootKey;

    /// @notice Mapping of addresses to their verification status
    mapping(address => bool) public isVerified;

    /// @notice Thrown when attestation timestamp is too old
    error KmsRootTooOld();
    /// @notice Thrown when input length is invalid (public key must be 64 bytes)
    error KmsRootLengthInvalid();

    /// @notice Emitted when the verifier contract address is updated
    /// @param verifier New verifier contract address
    /// @param old Previous verifier contract address
    event KmsRootUpdatedVerifier(
        IRiscZeroVerifier indexed verifier,
        IRiscZeroVerifier indexed old
    );
    /// @notice Emitted when the image ID is updated
    /// @param imageId New image ID
    /// @param old Previous image ID
    event KmsRootUpdatedImageId(bytes32 indexed imageId, bytes32 indexed old);
    /// @notice Emitted when PCR values are updated
    /// @param pcrs New PCR values
    /// @param old Previous PCR values
    event KmsRootUpdatedPcrs(bytes indexed pcrs, bytes indexed old);
    /// @notice Emitted when root key is updated
    /// @param rootKey New root key
    /// @param old Previous root key
    event KmsRootUpdatedRootKey(bytes indexed rootKey, bytes indexed old);
    /// @notice Emitted when an address is verified
    /// @param addr The verified address
    event KmsRootVerified(address indexed addr);

    /// @notice Initializes the KmsRoot contract
    /// @param _owner Address of the contract owner
    /// @param _verifier Address of the RISC Zero verifier contract
    /// @param _imageId Image ID for verification
    /// @param _pcrs Initial PCR values
    /// @param _rootKey Initial root key
    /// @param _maxAge Maximum age allowed for attestation timestamps
    constructor(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        bytes memory _pcrs,
        bytes memory _rootKey,
        uint256 _maxAge
    ) Ownable(_owner) {
        MAX_AGE = _maxAge;

        _updateVerifier(_verifier);
        _updateImageId(_imageId);
        _updatePcrs(_pcrs);
        _updateRootKey(_rootKey);
    }

    /// @notice Updates the RISC Zero verifier contract address
    /// @param _verifier New verifier contract address
    function updateVerifier(IRiscZeroVerifier _verifier) external onlyOwner {
        _updateVerifier(_verifier);
    }

    /// @notice Updates the image ID used for verification
    /// @param _imageId New image ID
    function updateImageId(bytes32 _imageId) external onlyOwner {
        _updateImageId(_imageId);
    }

    /// @notice Updates the PCR values
    /// @param _pcrs New PCR values
    function updatePcrs(bytes calldata _pcrs) external onlyOwner {
        _updatePcrs(_pcrs);
    }

    /// @notice Updates the root key
    /// @param _rootKey New root key
    function updateRootKey(bytes calldata _rootKey) external onlyOwner {
        _updateRootKey(_rootKey);
    }

    /// @notice Verifies a KMS attestation
    /// @param _signerPubkey Public key of the signer
    /// @param _seal RISC Zero seal for verification
    /// @param _timestampInMilliseconds Timestamp of the attestation in milliseconds
    /// @dev Verifies the attestation and marks the derived address as verified if successful
    function verify(
        bytes calldata _signerPubkey,
        bytes calldata _seal,
        uint64 _timestampInMilliseconds
    ) external {
        require(
            _timestampInMilliseconds > (block.timestamp - MAX_AGE) * 1000,
            KmsRootTooOld()
        );
        address _addr = _pubkeyToAddress(_signerPubkey);
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _timestampInMilliseconds,
                pcrs,
                rootKey,
                uint8(_signerPubkey.length),
                _signerPubkey,
                uint16(0)
            )
        );
        verifier.verify(_seal, imageId, _journalDigest);

        isVerified[_addr] = true;

        emit KmsRootVerified(_addr);
    }

    /// @notice Internal function to update the verifier contract
    /// @param _verifier New verifier contract address
    /// @dev Emits KmsRootUpdatedVerifier event
    function _updateVerifier(IRiscZeroVerifier _verifier) internal {
        emit KmsRootUpdatedVerifier(_verifier, verifier);
        verifier = _verifier;
    }

    /// @notice Internal function to update the image ID
    /// @param _imageId New image ID
    /// @dev Emits KmsRootUpdatedImageId event
    function _updateImageId(bytes32 _imageId) internal {
        emit KmsRootUpdatedImageId(_imageId, imageId);
        imageId = _imageId;
    }

    /// @notice Internal function to update PCR values
    /// @param _pcrs New PCR values
    /// @dev Emits KmsRootUpdatedPcrs event
    function _updatePcrs(bytes memory _pcrs) internal {
        emit KmsRootUpdatedPcrs(_pcrs, pcrs);
        pcrs = _pcrs;
    }

    /// @notice Internal function to update the root key
    /// @param _rootKey New root key
    /// @dev Emits KmsRootUpdatedRootKey event
    function _updateRootKey(bytes memory _rootKey) internal {
        emit KmsRootUpdatedRootKey(_rootKey, rootKey);
        rootKey = _rootKey;
    }

    /// @notice Converts a public key to an Ethereum address
    /// @param _pubkey Public key to convert
    /// @return Ethereum address derived from the public key
    /// @dev Expects a 64-byte public key and returns the keccak256 hash as an address
    function _pubkeyToAddress(
        bytes calldata _pubkey
    ) internal pure returns (address) {
        require(_pubkey.length == 64, KmsRootLengthInvalid());

        bytes32 _hash = keccak256(_pubkey);
        return address(uint160(uint256(_hash)));
    }
}
