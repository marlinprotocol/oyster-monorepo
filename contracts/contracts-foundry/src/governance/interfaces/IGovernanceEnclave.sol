// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

interface IGovernanceEnclave {
    function getImageId() external view returns (bytes32);

    function verifyKMSSig(bytes32 _imageId, bytes calldata _enclavePubKey, bytes calldata _kmsSig, bytes32 _proposalId)
        external
        view
        returns (bool);

    function verifyEnclaveSig(bytes memory _enclavePubKey, bytes memory _enclaveSig, bytes memory message)
        external
        pure
        returns (bool);

    function getNetworkHash() external view returns (bytes32);

    function getSupportedChainIdsLength() external view returns (uint256);

    function getSupportedChainIds() external view returns (uint256[] memory);

    function isChainSupported(uint256 _chainId) external view returns (bool);
}