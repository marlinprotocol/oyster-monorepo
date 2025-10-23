// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

contract MockEnclave is Test {
    bytes constant ENCLAVE_PUB_KEY =
        hex"d8ad28c9f74e8bf4eb9199e638b2df049282e9c28e40edd096b443ef95b3b829ed785629e1aab7ce66459c76c9888ea26a8eae3a401ac6532824bde249b3292e";
    bytes constant ENCLAVE_PRIV_KEY = hex"b763604770e22821286dd58419a0499c6793490d8584f4ac7803e526a0036673";
    // For testing purposes, use enclave key as KMS key (in production these would be different)
    uint256 constant KMS_ROOT_SERVER_PRIV_KEY = 0xb763604770e22821286dd58419a0499c6793490d8584f4ac7803e526a0036673;
    bytes constant KMS_ROOT_SERVER_PUB_KEY = ENCLAVE_PUB_KEY;
    uint256 constant POND_TOTAL_SUPPLY = 10_000_000 * 1e18; // 10M total supply

    // Getter functions for constants
    function getKmsSig(bytes32 _imageId, bytes32 _proposalId) public pure returns (bytes memory) {
        string memory uri = string(
            abi.encodePacked(
                "/derive/secp256k1/public?image_id=",
                _toHexStringWithNoPrefix(_imageId),
                "&path=",
                _toHexStringWithNoPrefix(_proposalId),
                "_result"
            )
        );
        bytes memory message = abi.encodePacked(bytes(uri), ENCLAVE_PUB_KEY);
        bytes32 messageHash = sha256(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KMS_ROOT_SERVER_PRIV_KEY, messageHash);
        return abi.encodePacked(r, s, v);
    }

    function getEnclavePubKey() public pure returns (bytes memory) {
        return ENCLAVE_PUB_KEY;
    }

    function getEnclavePrivKey() public pure returns (bytes memory) {
        return ENCLAVE_PRIV_KEY;
    }

    function _toHexStringWithNoPrefix(bytes32 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    // values in percentage (1e18 = 100%)
    struct VotePercentage {
        uint256 yes;
        uint256 no;
        uint256 abstain;
        uint256 noWithVeto;
    }

    function getResult(
        bytes32 _proposalId,
        bytes32 _imageId,
        VotePercentage memory _votePercentage,
        address _contractAddress,
        uint256 _proposedTimestamp,
        bytes32 _networkHash,
        bytes32 _contractConfigHash,
        bytes32 _voteHash
    ) public pure returns (IGovernanceTypes.SubmitResultInputParams memory) {
        bytes memory resultData = _formResultData(_proposalId, _votePercentage);
        bytes memory enclaveSig = _signResultData(
            resultData, _contractAddress, _proposedTimestamp, _networkHash, _contractConfigHash, _voteHash
        );

        return IGovernanceTypes.SubmitResultInputParams({
            kmsSig: getKmsSig(_imageId, _proposalId),
            enclavePubKey: ENCLAVE_PUB_KEY,
            enclaveSig: enclaveSig,
            resultData: resultData
        });
    }

    function _formResultData(bytes32 _proposalId, VotePercentage memory _votePercentage)
        internal
        pure
        returns (bytes memory)
    {
        uint256 yesVotes = (_votePercentage.yes * POND_TOTAL_SUPPLY) / 1e18;
        uint256 noVotes = (_votePercentage.no * POND_TOTAL_SUPPLY) / 1e18;
        uint256 abstainVotes = (_votePercentage.abstain * POND_TOTAL_SUPPLY) / 1e18;
        uint256 noWithVetoVotes = (_votePercentage.noWithVeto * POND_TOTAL_SUPPLY) / 1e18;

        IGovernanceTypes.VoteDecisionResult memory voteDecisionResult = IGovernanceTypes.VoteDecisionResult({
            yes: yesVotes,
            no: noVotes,
            abstain: abstainVotes,
            noWithVeto: noWithVetoVotes,
            totalVotingPower: POND_TOTAL_SUPPLY
        });

        return abi.encode(_proposalId, voteDecisionResult);
    }

    function _signResultData(
        bytes memory _resultData,
        address _contractAddress,
        uint256 _proposedTimestamp,
        bytes32 _networkHash,
        bytes32 _contractConfigHash,
        bytes32 _voteHash
    ) internal pure returns (bytes memory) {
        // Enclave will sign on this digest
        bytes32 contractDataHash =
            sha256(abi.encode(_contractAddress, _proposedTimestamp, _contractConfigHash, _networkHash, _voteHash));

        // Decode resultData to get proposalId and voteDecisionResult
        (bytes32 proposalId, IGovernanceTypes.VoteDecisionResult memory voteDecisionResult) =
            abi.decode(_resultData, (bytes32, IGovernanceTypes.VoteDecisionResult));

        bytes memory message = abi.encode(contractDataHash, proposalId, voteDecisionResult);

        bytes32 digest = sha256(message);
        uint256 privateKey = uint256(bytes32(ENCLAVE_PRIV_KEY));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
