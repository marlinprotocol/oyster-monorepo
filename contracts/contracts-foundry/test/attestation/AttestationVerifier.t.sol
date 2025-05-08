// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {IAccessControl} from "../../lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {AttestationVerifier} from "../../src/attestation/AttestationVerifier.sol";
import {IAttestationVerifier} from "../../src/attestation/IAttestationVerifier.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";
import {VerifiedKeys} from "../../src/attestation/VerifiedKeys.sol";

contract AttestationVerifierTestConstruction is Test {
    function test_Construction(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId
    ) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, IRiscZeroVerifier(address(0)));
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, bytes32(0));
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, new bytes(0));
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, 0);

        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, keccak256("DEFAULT_FAMILY"));

        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("APPROVER_ROLE"), _approver, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("REVOKER_ROLE"), _revoker, address(this));

        AttestationVerifier verifier =
            new AttestationVerifier(_admin, _approver, _revoker, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId);

        assertEq(address(verifier.verifier()), address(_verifier));
        assertEq(verifier.guestId(), _guestId);
        assertEq(verifier.rootKey(), _rootKey);
        assertEq(verifier.maxAgeMs(), _maxAgeMs);
        assertEq(verifier.images(_imageId), keccak256("DEFAULT_FAMILY"));
        assertTrue(verifier.hasRole(verifier.DEFAULT_ADMIN_ROLE(), _admin));
        assertTrue(verifier.hasRole(verifier.APPROVER_ROLE(), _approver));
        assertTrue(verifier.hasRole(verifier.REVOKER_ROLE(), _revoker));
    }
}

contract AttestationVerifierTestVerify is Test {
    AttestationVerifier verifier;
    address admin = makeAddr("admin");
    address approver = makeAddr("approver");
    address revoker = makeAddr("revoker");
    IRiscZeroVerifier riscZeroVerifier = IRiscZeroVerifier(makeAddr("verifier"));
    bytes32 guestId = bytes32(uint256(1));
    bytes rootKey = hex"010203";
    uint256 maxAgeMs = 2000;
    bytes32 imageId = bytes32(uint256(2));

    function setUp() public {
        verifier =
            new AttestationVerifier(admin, approver, revoker, riscZeroVerifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_Verify_ValidSignature() public {
        // generated using attestation-verifier.test.js
        bytes memory _enclavePubkey =
            hex"9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76";
        bytes memory _attestationPubkey =
            hex"9f82020b6e9431e8abcc0f1ce313248a10bc9e96e59b720dc3653398496c3c52dea402c5ef3a6780ccf1f0aeeaa68ae4e3f132496d011df322e84b171e82750d";
        bytes memory _userData = hex"12345678";
        uint64 _timestamp = 0x4e43046b;
        bytes memory _signature =
            hex"d24e2af7f09287b27e9cc3184c34a43bb02838e188b777852088d4155465865c730c5a1be77b9d76cbeb601b44453dc52abad202000bafd379ba6cbd98b3cc4d1b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(imageId, _timestamp, _attestationPubkey, _userData);
        vm.mockCall(address(riscZeroVerifier), abi.encode(), abi.encode());
        vm.warp(_timestamp / 1000);
        verifier.verifyEnclaveRiscZero(
            new bytes(0), IAttestationVerifier.Attestation(imageId, _timestamp, _enclavePubkey, _userData)
        );

        verifier.verify(_signature, attestation);
    }

    function test_Verify_InvalidSignature() public {
        // generated using attestation-verifier.test.js
        bytes memory _enclavePubkey =
            hex"9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76";
        bytes memory _attestationPubkey =
            hex"9f82020b6e9431e8abcc0f1ce313248a10bc9e96e59b720dc3653398496c3c52dea402c5ef3a6780ccf1f0aeeaa68ae4e3f132496d011df322e84b171e82750d";
        bytes memory _userData = hex"12345678";
        uint64 _timestamp = 0x4e43046b;
        bytes memory _signature =
            hex"d24e2af7f09287b27e9cc3184c34a43bb02838e188b777852088d4155465865c730c5a1be77b9d76cbeb601b44453dc52abad202000bafd379ba6cbd98b3cc4e1b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(imageId, _timestamp, _attestationPubkey, _userData);
        vm.mockCall(address(riscZeroVerifier), abi.encode(), abi.encode());
        vm.warp(_timestamp / 1000);
        verifier.verifyEnclaveRiscZero(
            new bytes(0), IAttestationVerifier.Attestation(imageId, _timestamp, _enclavePubkey, _userData)
        );
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifier.verify(_signature, attestation);
    }

    function test_Verify_UnverifiedKey() public {
        // generated using attestation-verifier.test.js
        bytes memory _attestationPubkey =
            hex"9f82020b6e9431e8abcc0f1ce313248a10bc9e96e59b720dc3653398496c3c52dea402c5ef3a6780ccf1f0aeeaa68ae4e3f132496d011df322e84b171e82750d";
        bytes memory _userData = hex"12345678";
        uint64 _timestamp = 0x4e43046b;
        bytes memory _signature =
            hex"d24e2af7f09287b27e9cc3184c34a43bb02838e188b777852088d4155465865c730c5a1be77b9d76cbeb601b44453dc52abad202000bafd379ba6cbd98b3cc4d1b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(imageId, _timestamp, _attestationPubkey, _userData);
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifier.verify(_signature, attestation);
    }

    function test_Verify_RevokedKey() public {
        // generated using attestation-verifier.test.js
        bytes memory _enclavePubkey =
            hex"9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76";
        bytes memory _attestationPubkey =
            hex"9f82020b6e9431e8abcc0f1ce313248a10bc9e96e59b720dc3653398496c3c52dea402c5ef3a6780ccf1f0aeeaa68ae4e3f132496d011df322e84b171e82750d";
        bytes memory _userData = hex"12345678";
        uint64 _timestamp = 0x4e43046b;
        bytes memory _signature =
            hex"d24e2af7f09287b27e9cc3184c34a43bb02838e188b777852088d4155465865c730c5a1be77b9d76cbeb601b44453dc52abad202000bafd379ba6cbd98b3cc4d1b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(imageId, _timestamp, _attestationPubkey, _userData);
        vm.mockCall(address(riscZeroVerifier), abi.encode(), abi.encode());
        vm.warp(_timestamp / 1000);
        verifier.verifyEnclaveRiscZero(
            new bytes(0), IAttestationVerifier.Attestation(imageId, _timestamp, _enclavePubkey, _userData)
        );
        vm.prank(revoker);
        verifier.revokeImage(imageId);
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifier.verify(_signature, attestation);
    }
}
