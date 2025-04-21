// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Interface for verifying images IDs
interface IKMSVerifiable {
    /// @notice Verifies the image Id for KMS derived keys
    /// @param _imageId Image id to verify
    /// @return True if the image id is verified
    function oysterKMSVerify(bytes32 _imageId) external returns (bool);
}
