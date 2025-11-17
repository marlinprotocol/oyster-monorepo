// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

interface IGovernanceEnclave {
    struct TokenNetworkConfig {
        bytes32 chainHash; // sha256(abi.encode(chainId, rpcUrls))
        address tokenAddress;
        string[] rpcUrls;
    }

    function getImageId() external view returns (bytes32);

    function verifyKMSSig(bytes32 _imageId, bytes calldata _enclavePubKey, bytes calldata _kmsSig, bytes32 _proposalId)
        external
        view
        returns (bool);

    function verifyEnclaveSig(bytes memory _enclavePubKey, bytes memory _enclaveSig, bytes32 _messageHash)
        external
        pure
        returns (bool);

    function getNetworkHash() external view returns (bytes32);

    function getSupportedChainIdsLength() external view returns (uint256);

    function getAllSupportedChainIds() external view returns (uint256[] memory);

    function isChainSupported(uint256 _chainId) external view returns (bool);
    
    function getTokenNetworkConfig(uint256 _chainId) external view returns (TokenNetworkConfig memory);
    
    function getPCRConfig() external view returns (bytes memory pcr0, bytes memory pcr1, bytes memory pcr2, bytes32 imageId);
}