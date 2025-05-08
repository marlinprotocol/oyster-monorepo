// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {IAccessControl} from "../../lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {AttestationAuther} from "../../src/attestation/AttestationAuther.sol";
import {IAttestationVerifier} from "../../src/attestation/IAttestationVerifier.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";
import {VerifiedKeys} from "../../src/attestation/VerifiedKeys.sol";

contract TestAttestationAuther is AttestationAuther, IAttestationVerifier {
    bool public shouldVerify;

    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family,
        bool _shouldVerify
    )
        AttestationAuther(_admin, _approver, _revoker, this, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId, _family)
    {
        shouldVerify = _shouldVerify;
    }

    function setShouldVerify(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    function verify(bytes memory, Attestation memory) external view {
        require(shouldVerify, "auther not verified");
    }
}

contract AttestationAutherTestConstruction is Test {
    function test_Construction(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family
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
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, _family);

        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("APPROVER_ROLE"), _approver, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("REVOKER_ROLE"), _revoker, address(this));

        TestAttestationAuther auther = new TestAttestationAuther(
            _admin, _approver, _revoker, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId, _family, true
        );

        assertTrue(auther.hasRole(auther.DEFAULT_ADMIN_ROLE(), _admin));
        assertTrue(auther.hasRole(auther.APPROVER_ROLE(), _approver));
        assertTrue(auther.hasRole(auther.REVOKER_ROLE(), _revoker));
        assertEq(address(auther.attestationVerifier()), address(auther));
        assertEq(auther.shouldVerify(), true);

        assertEq(address(auther.verifier()), address(_verifier));
        assertEq(auther.guestId(), _guestId);
        assertEq(auther.rootKey(), _rootKey);
        assertEq(auther.maxAgeMs(), _maxAgeMs);

        assertEq(auther.images(_imageId), _family);
    }
}

contract AttestationAutherTestUpdateVerifier is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_UpdateVerifier_Authorized(IRiscZeroVerifier newVerifier) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(newVerifier, verifier);

        vm.prank(admin);
        auther.updateVerifier(newVerifier);

        assertEq(address(auther.verifier()), address(newVerifier));
    }

    function test_UpdateVerifier_Unauthorized(IRiscZeroVerifier newVerifier, address nonAdmin) public {
        vm.assume(nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonAdmin, auther.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(nonAdmin);
        auther.updateVerifier(newVerifier);
    }
}

contract AttestationAutherTestUpdateGuestId is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_UpdateGuestId_Authorized(bytes32 newGuestId) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(newGuestId, guestId);

        vm.prank(admin);
        auther.updateGuestId(newGuestId);

        assertEq(auther.guestId(), newGuestId);
    }

    function test_UpdateGuestId_Unauthorized(bytes32 newGuestId, address nonAdmin) public {
        vm.assume(nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonAdmin, auther.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(nonAdmin);
        auther.updateGuestId(newGuestId);
    }
}

contract AttestationAutherTestUpdateRootKey is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_UpdateRootKey_Authorized(bytes calldata newRootKey) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(newRootKey, rootKey);

        vm.prank(admin);
        auther.updateRootKey(newRootKey);

        assertEq(auther.rootKey(), newRootKey);
    }

    function test_UpdateRootKey_Unauthorized(bytes calldata newRootKey, address nonAdmin) public {
        vm.assume(nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonAdmin, auther.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(nonAdmin);
        auther.updateRootKey(newRootKey);
    }
}

contract AttestationAutherTestUpdateMaxAge is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_UpdateMaxAge_Authorized(uint256 newMaxAge) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(newMaxAge, maxAgeMs);

        vm.prank(admin);
        auther.updateMaxAge(newMaxAge);

        assertEq(auther.maxAgeMs(), newMaxAge);
    }

    function test_UpdateMaxAge_Unauthorized(uint256 newMaxAge, address nonAdmin) public {
        vm.assume(nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonAdmin, auther.DEFAULT_ADMIN_ROLE()
            )
        );

        vm.prank(nonAdmin);
        auther.updateMaxAge(newMaxAge);
    }
}

contract AttestationAutherTestApproveImage is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_ApproveImage_Authorized(bytes32 _imageId, bytes32 _family) public {
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, _family);

        vm.prank(approver);
        bool result = auther.approveImage(_imageId, _family);

        assertTrue(result);
        assertEq(auther.images(_imageId), _family);
    }

    function test_ApproveImage_Unauthorized(bytes32 _imageId, bytes32 _family, address _nonApprover) public {
        vm.assume(_nonApprover != approver);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonApprover, auther.APPROVER_ROLE()
            )
        );

        vm.prank(_nonApprover);
        auther.approveImage(_imageId, _family);
    }
}

contract AttestationAutherTestRevokeImage is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_RevokeImage_Authorized() public {
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysRevoked(imageId, family);

        vm.prank(revoker);
        bool result = auther.revokeImage(imageId);

        assertTrue(result);
        assertEq(auther.images(imageId), bytes32(0));
    }

    function test_RevokeImage_Unauthorized(address _nonRevoker) public {
        vm.assume(_nonRevoker != revoker);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, _nonRevoker, auther.REVOKER_ROLE()
            )
        );

        vm.prank(_nonRevoker);
        auther.revokeImage(imageId);
    }
}

contract AttestationAutherTestVerifyEnclaveRiscZero is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_VerifyEnclaveRiscZero_Valid(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes calldata _userData,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _timestampMs, imageId, rootKey, uint8(_pubkey.length), _pubkey, uint16(_userData.length), _userData
            )
        );
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        vm.warp(4);

        bytes32 _addr = bytes32(uint256(uint160(uint256(keccak256(_pubkey)))));
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysVerified(_addr, imageId, _pubkey);

        auther.verifyEnclaveRiscZero(_seal, IAttestationVerifier.Attestation(imageId, _timestampMs, _pubkey, _userData));

        assertEq(auther.keys(_addr), imageId);
    }

    function test_VerifyEnclaveRiscZero_TooOld(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes calldata _userData,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 0, 2000));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierTooOld.selector));
        vm.warp(4);

        auther.verifyEnclaveRiscZero(_seal, IAttestationVerifier.Attestation(imageId, _timestampMs, _pubkey, _userData));
    }

    function test_VerifyEnclaveRiscZero_InvalidLength(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes calldata _userData,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length != 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _timestampMs, imageId, rootKey, uint8(_pubkey.length), _pubkey, uint16(_userData.length), _userData
            )
        );
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        vm.expectRevert(abi.encodeWithSelector(AttestationAuther.AttestationAutherPubkeyInvalid.selector));
        vm.warp(4);

        auther.verifyEnclaveRiscZero(_seal, IAttestationVerifier.Attestation(imageId, _timestampMs, _pubkey, _userData));
    }

    function test_VerifyEnclaveRiscZero_FailedVerification(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes calldata _userData,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _timestampMs, imageId, rootKey, uint8(_pubkey.length), _pubkey, uint16(_userData.length), _userData
            )
        );
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCallRevert(address(verifier), _calldata, "not verified");
        vm.expectRevert("not verified");
        vm.warp(4);

        auther.verifyEnclaveRiscZero(_seal, IAttestationVerifier.Attestation(imageId, _timestampMs, _pubkey, _userData));
    }
}

contract AttestationAutherTestVerifyEnclaveSignature is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());

        auther = new TestAttestationAuther(
            admin, approver, revoker, verifier, guestId, rootKey, maxAgeMs, imageId, family, true
        );
    }

    function test_VerifyEnclaveSignature_Valid(
        bytes memory _signature,
        bytes memory _publicKey,
        bytes memory _userData,
        uint64 _timestampMs
    ) public {
        vm.assume(_publicKey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        IAttestationVerifier.Attestation memory attestation = IAttestationVerifier.Attestation({
            imageId: imageId,
            timestampMs: _timestampMs,
            publicKey: _publicKey,
            userData: _userData
        });
        bytes32 _addr = bytes32(uint256(uint160(uint256(keccak256(_publicKey)))));
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysVerified(_addr, imageId, _publicKey);
        vm.warp(4);

        auther.verifyEnclaveSignature(_signature, attestation);

        assertEq(auther.keys(_addr), imageId);
    }

    function test_VerifyEnclaveSignature_Invalid(
        bytes memory _signature,
        bytes memory _publicKey,
        bytes memory _userData,
        uint64 _timestampMs
    ) public {
        vm.assume(_publicKey.length == 64);
        auther.setShouldVerify(false);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        IAttestationVerifier.Attestation memory attestation = IAttestationVerifier.Attestation({
            imageId: imageId,
            timestampMs: _timestampMs,
            publicKey: _publicKey,
            userData: _userData
        });
        vm.expectRevert("auther not verified");
        vm.warp(4);

        auther.verifyEnclaveSignature(_signature, attestation);
    }

    function test_VerifyEnclaveSignature_Expired(
        bytes memory _signature,
        bytes memory _publicKey,
        bytes memory _userData,
        uint64 _timestampMs
    ) public {
        vm.assume(_publicKey.length == 64);
        _timestampMs = uint64(bound(_timestampMs, 0, 2000));
        IAttestationVerifier.Attestation memory attestation = IAttestationVerifier.Attestation({
            imageId: imageId,
            timestampMs: _timestampMs,
            publicKey: _publicKey,
            userData: _userData
        });
        vm.warp(4);

        vm.expectRevert(abi.encodeWithSelector(AttestationAuther.AttestationAutherTooOld.selector));
        auther.verifyEnclaveSignature(_signature, attestation);
    }
}
