// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";

import {IKMSVerifiable} from "./IKMSVerifiable.sol";

/// @title Sample KMS Verifiable Contract
/// @notice Manages list of image IDs allowed to derive keys
contract KmsVerifiable is Ownable, IKMSVerifiable {
    /// @notice Mapping of verified image IDs
    mapping(bytes32 => bool) public images;

    /// @notice Event emitted when an image is approved
    event ImageApproved(bytes32 imageId);

    /// @notice Event emitted when an image is revoked
    event ImageRevoked(bytes32 imageId);

    constructor(bytes32[] memory _imageIds) Ownable(msg.sender) {
        _approveImages(_imageIds);
    }

    function _approveImages(bytes32[] memory _imageIds) internal {
        for (uint256 i = 0; i < _imageIds.length; i++) {
            images[_imageIds[i]] = true;
            emit ImageApproved(_imageIds[i]);
        }
    }

    function approveImages(bytes32[] calldata _imageIds) external onlyOwner {
        _approveImages(_imageIds);
    }

    function revokeImages(bytes32[] calldata _imageIds) external onlyOwner {
        for (uint256 i = 0; i < _imageIds.length; i++) {
            delete images[_imageIds[i]];
            emit ImageRevoked(_imageIds[i]);
        }
    }

    function oysterKMSVerify(bytes32 _imageId) external view override returns (bool) {
        return images[_imageId];
    }
}
