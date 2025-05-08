// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {KmsRoot} from "../../src/kms/KmsRoot.sol";

import {IAccessControl} from "../../lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";
import {VerifiedKeys} from "../../src/attestation/VerifiedKeys.sol";
import {IAttestationVerifier} from "../../src/attestation/IAttestationVerifier.sol";

contract KmsRootTestConstruction is Test {
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

        KmsRoot _kmsRoot = new KmsRoot(_admin, _approver, _revoker, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId);

        assertEq(address(_kmsRoot.verifier()), address(_verifier));
        assertEq(_kmsRoot.guestId(), _guestId);
        assertEq(_kmsRoot.rootKey(), _rootKey);
        assertEq(_kmsRoot.maxAgeMs(), _maxAgeMs);
        assertTrue(_kmsRoot.hasRole(_kmsRoot.DEFAULT_ADMIN_ROLE(), _admin));
        assertTrue(_kmsRoot.hasRole(_kmsRoot.APPROVER_ROLE(), _approver));
        assertTrue(_kmsRoot.hasRole(_kmsRoot.REVOKER_ROLE(), _revoker));
        assertEq(_kmsRoot.images(_imageId), _kmsRoot.DEFAULT_FAMILY());
    }
}

contract KmsRootTestUpdateVerifier is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateVerifier_FromAdmin(IRiscZeroVerifier _verifier) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, verifier);

        vm.prank(admin);
        kmsRoot.updateVerifier(_verifier);

        assertEq(address(kmsRoot.verifier()), address(_verifier));
    }

    function test_UpdateVerifier_FromNonAdmin(IRiscZeroVerifier _verifier, address _nonAdmin) public {
        vm.assume(_nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonAdmin, kmsRoot.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(_nonAdmin);
        kmsRoot.updateVerifier(_verifier);
    }
}

contract KmsRootTestUpdateGuestId is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateGuestId_FromAdmin(bytes32 _guestId) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, guestId);

        vm.prank(admin);
        kmsRoot.updateGuestId(_guestId);

        assertEq(kmsRoot.guestId(), _guestId);
    }

    function test_UpdateGuestId_FromNonAdmin(bytes32 _guestId, address _nonAdmin) public {
        vm.assume(_nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonAdmin, kmsRoot.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(_nonAdmin);
        kmsRoot.updateGuestId(_guestId);
    }
}

contract KmsRootTestUpdateRootKey is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateRootKey_FromAdmin(bytes calldata _rootKey) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, rootKey);

        vm.prank(admin);
        kmsRoot.updateRootKey(_rootKey);

        assertEq(kmsRoot.rootKey(), _rootKey);
    }

    function test_UpdateRootKey_FromNonAdmin(bytes calldata _rootKey, address _nonAdmin) public {
        vm.assume(_nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonAdmin, kmsRoot.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(_nonAdmin);
        kmsRoot.updateRootKey(_rootKey);
    }
}

contract KmsRootTestUpdateMaxAge is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateMaxAge_FromAdmin(uint256 _maxAgeMs) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, maxAgeMs);

        vm.prank(admin);
        kmsRoot.updateMaxAge(_maxAgeMs);

        assertEq(kmsRoot.maxAgeMs(), _maxAgeMs);
    }

    function test_UpdateMaxAge_FromNonAdmin(uint256 _maxAgeMs, address _nonAdmin) public {
        vm.assume(_nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonAdmin, kmsRoot.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(_nonAdmin);
        kmsRoot.updateMaxAge(_maxAgeMs);
    }
}

contract KmsRootTestApproveImage is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_ApproveImage_FromApprover(bytes32 _imageId, bytes32 _family) public {
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, _family);

        vm.prank(approver);
        kmsRoot.approveImage(_imageId, _family);

        assertEq(kmsRoot.images(_imageId), _family);
    }

    function test_ApproveImage_FromNonApprover(bytes32 _imageId, bytes32 _family, address _nonApprover) public {
        vm.assume(_nonApprover != approver);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonApprover, kmsRoot.APPROVER_ROLE()
            )
        );

        vm.prank(_nonApprover);
        kmsRoot.approveImage(_imageId, _family);
    }
}

contract KmsRootTestRevokeImage is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_RevokeImage_FromRevoker(bytes32 _imageId, bytes32 _family) public {
        vm.prank(approver);
        kmsRoot.approveImage(_imageId, _family);

        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysRevoked(_imageId, _family);

        vm.prank(revoker);
        kmsRoot.revokeImage(_imageId);

        assertEq(kmsRoot.images(_imageId), bytes32(0));
    }

    function test_RevokeImage_FromNonRevoker(bytes32 _imageId, bytes32 _family, address _nonRevoker) public {
        vm.prank(approver);
        kmsRoot.approveImage(_imageId, _family);

        vm.assume(_nonRevoker != revoker);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonRevoker, kmsRoot.REVOKER_ROLE()
            )
        );

        vm.prank(_nonRevoker);
        kmsRoot.revokeImage(_imageId);
    }
}

contract KmsRootTestVerify is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_Verify_Valid(bytes calldata _seal, bytes calldata _pubkey, bytes32 _imageId, uint64 _timestampMs)
        public
    {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        bytes32 _journalDigest =
            sha256(abi.encodePacked(_timestampMs, _imageId, rootKey, uint8(_pubkey.length), _pubkey, uint16(0)));
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        bytes32 _addr = bytes32(uint256(uint160(uint256(keccak256(_pubkey)))));
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysVerified(_addr, _imageId, _pubkey);
        vm.warp(4);

        kmsRoot.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, new bytes(0)));

        assertEq(kmsRoot.keys(_addr), _imageId);
    }

    function test_Verify_TooOld(bytes calldata _seal, bytes calldata _pubkey, bytes32 _imageId, uint64 _timestampMs)
        public
    {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 0, 2000));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierTooOld.selector));
        vm.warp(4);

        kmsRoot.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, new bytes(0)));
    }

    function test_Verify_InvalidLength(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length != 64);
        vm.assume(_pubkey.length < 256);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        bytes32 _journalDigest =
            sha256(abi.encodePacked(_timestampMs, _imageId, rootKey, uint8(_pubkey.length), _pubkey, uint16(0)));
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        vm.expectRevert(abi.encodeWithSelector(KmsRoot.KmsRootLengthInvalid.selector));
        vm.warp(4);

        kmsRoot.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, new bytes(0)));
    }

    function test_Verify_InvalidSeal(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        vm.mockCallRevert(address(verifier), abi.encode(), "0x12345678");
        vm.expectRevert("0x12345678");
        vm.warp(4);

        kmsRoot.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, new bytes(0)));
    }
}

contract KmsRootTestIsKeyVerified is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_IsKeyVerified_Verified(bytes calldata _seal, bytes calldata _pubkey, uint64 _timestampMs) public {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        address _addr = address(uint160(uint256(keccak256(_pubkey))));
        vm.mockCall(address(verifier), abi.encode(), abi.encode());
        vm.warp(4);
        kmsRoot.verify(_seal, IAttestationVerifier.Attestation(imageId, _timestampMs, _pubkey, new bytes(0)));

        bool res = kmsRoot.isVerified(_addr);

        assertTrue(res);
    }

    function test_IsKeyVerified_NotVerified(address _addr) public view {
        bool res = kmsRoot.isVerified(_addr);

        assertFalse(res);
    }

    function test_IsKeyVerified_Revoked(bytes calldata _seal, bytes calldata _pubkey, uint64 _timestampMs) public {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        address _addr = address(uint160(uint256(keccak256(_pubkey))));
        vm.mockCall(address(verifier), abi.encode(), abi.encode());
        vm.warp(4);
        kmsRoot.verify(_seal, IAttestationVerifier.Attestation(imageId, _timestampMs, _pubkey, new bytes(0)));
        vm.prank(revoker);
        kmsRoot.revokeImage(imageId);

        bool res = kmsRoot.isVerified(_addr);

        assertFalse(res);
    }
}
