// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../secret-storage/SecretStore.sol";
import "../secret-storage/Executors.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "../interfaces/IAttestationVerifier.sol";
import "../AttestationAuther.sol";

contract TeeManagerMock is Context, AttestationAuther {

    Executors public EXECUTORS;
    SecretStore public SECRET_STORE;
    uint256 public immutable MIN_STAKE_AMOUNT;

    struct TeeNode {
        uint256 stakeAmount;
        address owner;
        uint8 env;
        bool draining;
    }

    // enclaveAddress => TEE node details
    mapping(address => TeeNode) public teeNodes;

    event TeeManagerMockExecutorSlashed();
    event TeeManagerMockStoreSlashed(
        address _enclaveAddress,
        uint256 _missedEpochsCount,
        address _recipient
    );

    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        uint256 _minStakeAmount
    ) AttestationAuther(attestationVerifier, maxAge) {
        MIN_STAKE_AMOUNT = _minStakeAmount;
    }

    function setExecutors(Executors _executors) external {
        EXECUTORS = _executors;
    }

    function setSecretStore(SecretStore _secretStore) external {
        SECRET_STORE = _secretStore;
    }

    function registerTeeNode(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        teeNodes[enclaveAddress].env = _env;
        teeNodes[enclaveAddress].owner = _msgSender();
        teeNodes[enclaveAddress].stakeAmount = _stakeAmount;

        if(address(EXECUTORS) != address(0))
            EXECUTORS.registerExecutor(enclaveAddress, _jobCapacity, _env, _stakeAmount);
        else if(address(SECRET_STORE) != address(0))
            SECRET_STORE.registerSecretStore(enclaveAddress, _storageCapacity, _env, _stakeAmount);
    }

    function deregisterTeeNode(address _enclaveAddress) external {
        if(address(EXECUTORS) != address(0))
            EXECUTORS.deregisterExecutor(_enclaveAddress);
        else if(address(SECRET_STORE) != address(0))
            SECRET_STORE.deregisterSecretStore(_enclaveAddress);
        delete teeNodes[_enclaveAddress];
    }

    function drainTeeNode(address _enclaveAddress) external {
        teeNodes[_enclaveAddress].draining = true;
        uint8 env = teeNodes[_enclaveAddress].env;
        if(address(EXECUTORS) != address(0))
            EXECUTORS.drainExecutor(_enclaveAddress, env);
        else if(address(SECRET_STORE) != address(0))
            SECRET_STORE.drainSecretStore(_enclaveAddress, env, teeNodes[_enclaveAddress].owner);
    }

    function reviveTeeNode(address _enclaveAddress) external {
        teeNodes[_enclaveAddress].draining = false;
        TeeNode memory teeNode = teeNodes[_enclaveAddress];
        if(address(EXECUTORS) != address(0))
            EXECUTORS.reviveExecutor(_enclaveAddress, teeNode.env, teeNode.stakeAmount);
        else if(address(SECRET_STORE) != address(0))
            SECRET_STORE.reviveSecretStore(_enclaveAddress, teeNode.env, teeNode.stakeAmount);
    }

    function addTeeNodeStake(
        address _enclaveAddress,
        uint256 _amount
    ) external {
        TeeNode memory teeNode = teeNodes[_enclaveAddress];
        uint256 updatedStake = teeNode.stakeAmount + _amount;
        teeNodes[_enclaveAddress].stakeAmount = updatedStake;
        if(address(EXECUTORS) != address(0))
            EXECUTORS.addExecutorStake(_enclaveAddress, teeNode.env, updatedStake);
        else if(address(SECRET_STORE) != address(0))
            SECRET_STORE.addSecretStoreStake(_enclaveAddress, teeNode.env, updatedStake);
    }

    function removeTeeNodeStake(
        address _enclaveAddress,
        uint256 _amount
    ) external {
        teeNodes[_enclaveAddress].stakeAmount -= _amount;
        if(address(EXECUTORS) != address(0))
            EXECUTORS.removeExecutorStake(_enclaveAddress);
        else if(address(SECRET_STORE) != address(0))
            SECRET_STORE.removeSecretStoreStake(_enclaveAddress);
    }

    // --------------------------------- Executors functions start ---------------------------------

    function slashExecutor(
        address _enclaveAddress,
        address _recipient
    ) external returns (uint256) {
        emit TeeManagerMockExecutorSlashed();
        return 0;
    }

    // ---------------------------------- Executors functions end -------------------------------------

    // --------------------------------- Secret Store functions start ---------------------------------

    function slashStore(
        address _enclaveAddress,
        uint256 _missedEpochsCount,
        address _recipient
    ) external {
        emit TeeManagerMockStoreSlashed(_enclaveAddress, _missedEpochsCount, _recipient);
    }

    // --------------------------------- Secret Store functions end ---------------------------------

    function updateTreeState(
        address _enclaveAddress
    ) external {
        TeeNode memory teeNode = teeNodes[_enclaveAddress];
        if (!teeNode.draining) {
            // node might have been deleted due to max job capacity reached
            // if stakes are greater than minStakes then update the stakes for executors in tree if it already exists else add with latest stake
            if (teeNode.stakeAmount >= MIN_STAKE_AMOUNT) {
                if(address(EXECUTORS) != address(0))
                    EXECUTORS.upsertTreeNode(teeNode.env, _enclaveAddress, teeNode.stakeAmount);
                if(address(SECRET_STORE) != address(0))
                    SECRET_STORE.upsertTreeNode(teeNode.env, _enclaveAddress, teeNode.stakeAmount);
            }
            // remove node from tree if stake falls below min level
            else {
                if(address(EXECUTORS) != address(0))
                    EXECUTORS.deleteTreeNodeIfPresent(teeNode.env, _enclaveAddress);
                if(address(SECRET_STORE) != address(0))
                    SECRET_STORE.deleteTreeNodeIfPresent(teeNode.env, _enclaveAddress);
            }
        }
    }

    function getTeeNodesStake(
        address[] memory _enclaveAddresses
    ) external view returns (uint256[] memory) {
        uint256 len = _enclaveAddresses.length;
        uint256[] memory stakeAmounts = new uint256[](len);
        for (uint256 index = 0; index < len; index++)
            stakeAmounts[index] = teeNodes[_enclaveAddresses[index]].stakeAmount;

        return stakeAmounts;
    }

}
