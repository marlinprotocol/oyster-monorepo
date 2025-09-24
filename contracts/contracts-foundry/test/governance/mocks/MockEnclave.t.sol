// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

contract MockEnclave is Test {
    bytes constant KMS_SIG =
        hex"ad654742afd06eec3921f718fe1570f3d316f38f72a91e2845aaf66de701ba047b4b1e9925143586b0793eb46733dfc579920d03608a318ae82776854fa656891c";
    bytes constant ENCLAVE_PUB_KEY =
        hex"d8ad28c9f74e8bf4eb9199e638b2df049282e9c28e40edd096b443ef95b3b829ed785629e1aab7ce66459c76c9888ea26a8eae3a401ac6532824bde249b3292e";
    bytes constant ENCLAVE_PRIV_KEY = hex"b763604770e22821286dd58419a0499c6793490d8584f4ac7803e526a0036673";
    uint256 constant POND_TOTAL_SUPPLY = 10_000_000 * 1e18; // 10M total supply

    // values in percentage (1e18 = 100%)
    struct VotePercentage {
        uint256 yes;
        uint256 no;
        uint256 abstain;
        uint256 noWithVeto;
    }

    function getResult(
        bytes32 _proposalId,
        VotePercentage memory _votePercentage,
        address _contractAddress,
        uint256 _proposedTimestamp,
        bytes32 _networkHash,
        bytes32 _voteHash
    ) public pure returns (IGovernanceTypes.SubmitResultInputParams memory) {
        bytes memory resultData = _formResultData(_proposalId, _votePercentage);
        bytes memory enclaveSig =
            _signResultData(resultData, _contractAddress, _proposedTimestamp, _networkHash, _voteHash);

        return IGovernanceTypes.SubmitResultInputParams({
            kmsSig: KMS_SIG,
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
        bytes32 _voteHash
    ) internal pure returns (bytes memory) {
        // Enclave will sign on this digest
        bytes32 contractDataHash = sha256(abi.encode(_contractAddress, _proposedTimestamp, _networkHash, _voteHash));

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
